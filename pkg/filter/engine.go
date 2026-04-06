package filter

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// FilterEngine wraps a Lua VM and optional rate limiter for one filter hook.
type FilterEngine struct {
	mu       sync.Mutex
	vm       *lua.LState
	filterFn *lua.LFunction
	rl       *RateLimiter // nil for route filters
}

// NewFilterEngine creates a filter engine from a Lua script string.
// If script starts with "@", the rest is treated as a file path.
// If rateCfg is non-nil, a rate limiter is attached (for mcast filters).
func NewFilterEngine(script string, rateCfg *RateLimitConfig) (*FilterEngine, error) {
	// Load script content
	code := script
	if strings.HasPrefix(script, "@") {
		data, err := os.ReadFile(script[1:])
		if err != nil {
			return nil, fmt.Errorf("load filter script %s: %w", script[1:], err)
		}
		code = string(data)
	}

	vm := lua.NewState(lua.Options{SkipOpenLibs: true})
	// Only open safe libs
	lua.OpenBase(vm)
	lua.OpenString(vm)
	lua.OpenMath(vm)
	lua.OpenTable(vm)

	if err := vm.DoString(code); err != nil {
		vm.Close()
		return nil, fmt.Errorf("compile filter script: %w", err)
	}

	fn := vm.GetGlobal("filter")
	filterFn, ok := fn.(*lua.LFunction)
	if !ok {
		vm.Close()
		return nil, fmt.Errorf("filter script must define a global function 'filter'")
	}

	e := &FilterEngine{
		vm:       vm,
		filterFn: filterFn,
	}

	if rateCfg != nil {
		e.rl = NewRateLimiter(rateCfg.PerMAC, rateCfg.PerClient)
	}

	return e, nil
}

// FilterMcast checks rate limit then calls the Lua filter on an Ethernet frame.
// Returns true if the packet should be accepted.
func (e *FilterEngine) FilterMcast(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}

	// Extract src MAC for rate limiting
	srcMAC := net.HardwareAddr(frame[6:12]).String()

	// Rate limit check (fast path, no Lua)
	if e.rl != nil && !e.rl.Allow(srcMAC) {
		return false
	}

	// Build Lua table
	dstMAC := net.HardwareAddr(frame[0:6]).String()
	ethertype := binary.BigEndian.Uint16(frame[12:14])

	e.mu.Lock()
	defer e.mu.Unlock()

	pkt := e.vm.NewTable()
	pkt.RawSetString("src_mac", lua.LString(srcMAC))
	pkt.RawSetString("dst_mac", lua.LString(dstMAC))
	pkt.RawSetString("ethertype", lua.LNumber(ethertype))
	pkt.RawSetString("size", lua.LNumber(len(frame)))

	// Parse IPv6 + ICMPv6 convenience fields
	if ethertype == 0x86dd && len(frame) >= 54 {
		nextHeader := frame[20]
		pkt.RawSetString("ipv6_next_header", lua.LNumber(nextHeader))
		if nextHeader == 58 && len(frame) >= 55 { // ICMPv6
			icmpv6Type := frame[54]
			pkt.RawSetString("icmpv6_type", lua.LNumber(icmpv6Type))
		}
	}

	return e.callFilter(pkt)
}

// FilterRoute calls the Lua filter on a route entry.
// Returns true if the route should be accepted.
func (e *FilterEngine) FilterRoute(mac string, ip string, isDelete bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	route := e.vm.NewTable()
	route.RawSetString("mac", lua.LString(mac))
	route.RawSetString("ip", lua.LString(ip))
	route.RawSetString("is_delete", lua.LBool(isDelete))

	return e.callFilter(route)
}

// callFilter invokes the Lua filter function. Must be called with e.mu held.
func (e *FilterEngine) callFilter(arg *lua.LTable) bool {
	if err := e.vm.CallByParam(lua.P{
		Fn:      e.filterFn,
		NRet:    1,
		Protect: true,
	}, arg); err != nil {
		log.Printf("[Filter] Lua error: %v", err)
		return true // fail-open on Lua errors
	}

	ret := e.vm.Get(-1)
	e.vm.Pop(1)

	if b, ok := ret.(lua.LBool); ok {
		return bool(b)
	}
	return true // fail-open on unexpected return type
}

// Close releases the Lua VM.
func (e *FilterEngine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vm.Close()
}
