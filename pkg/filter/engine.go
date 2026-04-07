package filter

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"

	"vxlan-controller/pkg/vlog"
)

// FilterEngine wraps a Lua VM and optional rate limiter for one filter hook.
type FilterEngine struct {
	mu       sync.Mutex
	vm       *lua.LState
	filterFn *lua.LFunction
	rl       *RateLimiter // nil for route filters
}

// NewFilterEngine creates a filter engine from a Lua script string.
// If script starts with "@", the rest is treated as a file path (resolved relative to baseDir).
// If rateCfg is non-nil, a rate limiter is attached (for mcast filters).
// baseDir is used for resolving @file paths and Lua require() calls.
func NewFilterEngine(script string, rateCfg *RateLimitConfig, baseDir string) (*FilterEngine, error) {
	// Load script content
	code := script
	if strings.HasPrefix(script, "@") {
		fpath := script[1:]
		if baseDir != "" && !filepath.IsAbs(fpath) {
			fpath = filepath.Join(baseDir, fpath)
		}
		data, err := os.ReadFile(fpath)
		if err != nil {
			return nil, fmt.Errorf("load filter script %s: %w", fpath, err)
		}
		code = string(data)
	}

	vm := lua.NewState(lua.Options{SkipOpenLibs: true})
	// Only open safe libs
	lua.OpenBase(vm)
	lua.OpenString(vm)
	lua.OpenMath(vm)
	lua.OpenTable(vm)

	// Register Go helpers (ip_in_cidr, log, etc.)
	registerHelpers(vm)
	// Register require() with disk resolution + built-in fallback
	registerRequire(vm, baseDir)

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

// registerRequire adds a require() global to the Lua VM that loads modules.
// Resolution order: disk file (relative to baseDir) → built-in module.
// Module names use dots as separators (e.g. require("lib.helpers")
// loads <baseDir>/lib/helpers.lua). Results are cached so each module loads once.
func registerRequire(vm *lua.LState, baseDir string) {
	cache := make(map[string]lua.LValue)
	vm.SetGlobal("require", vm.NewFunction(func(L *lua.LState) int {
		mod := L.CheckString(1)
		if cached, ok := cache[mod]; ok {
			L.Push(cached)
			return 1
		}

		var code string

		// Try disk first (if baseDir is set)
		if baseDir != "" {
			relPath := strings.ReplaceAll(mod, ".", string(filepath.Separator)) + ".lua"
			fullPath := filepath.Join(baseDir, relPath)
			if data, err := os.ReadFile(fullPath); err == nil {
				code = string(data)
			}
		}

		// Fall back to built-in modules
		if code == "" {
			builtin, ok := builtinModules[mod]
			if !ok {
				L.RaiseError("require %q: module not found", mod)
				return 0
			}
			code = builtin
		}

		if err := L.DoString(code); err != nil {
			L.RaiseError("require %q: %v", mod, err)
			return 0
		}
		// DoString pushes return values; capture top of stack
		ret := L.Get(-1)
		if ret == lua.LNil {
			ret = lua.LTrue // marker: module loaded but returned nothing
		}
		cache[mod] = ret
		L.Push(ret)
		return 1
	}))
}

// FilterMcast checks rate limit then calls the Lua filter on an Ethernet frame.
// Returns (accepted, reason, detail).
// Reason is "rate_limited" for rate limiter, or the string returned by Lua.
// If accepted is true, reason and detail should be discarded by the caller.
func (e *FilterEngine) FilterMcast(frame []byte) (bool, string, string) {
	if len(frame) < 14 {
		return false, "short_frame", ""
	}

	// Extract src MAC for rate limiting
	srcMAC := net.HardwareAddr(frame[6:12]).String()

	// Rate limit check (fast path, no Lua)
	if e.rl != nil && !e.rl.Allow(srcMAC) {
		return false, "rate_limited", ""
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

	// Parse IPv4 fields
	if ethertype == 0x0800 && len(frame) >= 34 {
		ipProtocol := frame[23]
		pkt.RawSetString("ip_protocol", lua.LNumber(ipProtocol))
		// src_ip, dst_ip
		pkt.RawSetString("src_ip", lua.LString(net.IP(frame[26:30]).String()))
		pkt.RawSetString("dst_ip", lua.LString(net.IP(frame[30:34]).String()))
		// IPv4 header length (IHL) in 32-bit words
		ihl := int(frame[14]&0x0f) * 4
		if ipProtocol == 17 && len(frame) >= 14+ihl+4 { // UDP
			srcPort := binary.BigEndian.Uint16(frame[14+ihl : 14+ihl+2])
			dstPort := binary.BigEndian.Uint16(frame[14+ihl+2 : 14+ihl+4])
			pkt.RawSetString("src_port", lua.LNumber(srcPort))
			pkt.RawSetString("dst_port", lua.LNumber(dstPort))
		} else if ipProtocol == 6 && len(frame) >= 14+ihl+4 { // TCP
			srcPort := binary.BigEndian.Uint16(frame[14+ihl : 14+ihl+2])
			dstPort := binary.BigEndian.Uint16(frame[14+ihl+2 : 14+ihl+4])
			pkt.RawSetString("src_port", lua.LNumber(srcPort))
			pkt.RawSetString("dst_port", lua.LNumber(dstPort))
			// tcp_flags: byte 13 of TCP header (offset from IP header end)
			if len(frame) >= 14+ihl+14 {
				pkt.RawSetString("tcp_flags", lua.LNumber(frame[14+ihl+13]))
			}
		} else if ipProtocol == 1 && len(frame) >= 14+ihl+2 { // ICMPv4
			pkt.RawSetString("icmp_type", lua.LNumber(frame[14+ihl]))
			pkt.RawSetString("icmp_code", lua.LNumber(frame[14+ihl+1]))
		}
	}

	// Parse ARP fields
	if ethertype == 0x0806 && len(frame) >= 42 {
		pkt.RawSetString("arp_op", lua.LNumber(binary.BigEndian.Uint16(frame[20:22])))
		pkt.RawSetString("arp_sender_ip", lua.LString(net.IP(frame[28:32]).String()))
		pkt.RawSetString("arp_target_ip", lua.LString(net.IP(frame[38:42]).String()))
	}

	// Parse IPv6 fields
	if ethertype == 0x86dd && len(frame) >= 54 {
		nextHeader := frame[20]
		pkt.RawSetString("ipv6_next_header", lua.LNumber(nextHeader))
		pkt.RawSetString("ip_protocol", lua.LNumber(nextHeader))
		// src_ip, dst_ip (IPv6: bytes 8-24 src, 24-40 from IPv6 header start at offset 14)
		pkt.RawSetString("src_ip", lua.LString(net.IP(frame[22:38]).String()))
		pkt.RawSetString("dst_ip", lua.LString(net.IP(frame[38:54]).String()))
		if nextHeader == 58 && len(frame) >= 56 { // ICMPv6
			pkt.RawSetString("icmpv6_type", lua.LNumber(frame[54]))
			pkt.RawSetString("icmpv6_code", lua.LNumber(frame[55]))
		} else if nextHeader == 17 && len(frame) >= 58 { // UDP
			srcPort := binary.BigEndian.Uint16(frame[54:56])
			dstPort := binary.BigEndian.Uint16(frame[56:58])
			pkt.RawSetString("src_port", lua.LNumber(srcPort))
			pkt.RawSetString("dst_port", lua.LNumber(dstPort))
		} else if nextHeader == 6 && len(frame) >= 68 { // TCP
			srcPort := binary.BigEndian.Uint16(frame[54:56])
			dstPort := binary.BigEndian.Uint16(frame[56:58])
			pkt.RawSetString("src_port", lua.LNumber(srcPort))
			pkt.RawSetString("dst_port", lua.LNumber(dstPort))
			pkt.RawSetString("tcp_flags", lua.LNumber(frame[67]))
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

	accepted, _, _ := e.callFilter(route)
	return accepted
}

// callFilter invokes the Lua filter function. Must be called with e.mu held.
// Lua return values (3): accepted (bool), reason (string), detail (string).
// If accepted is true, reason and detail are discarded by callers.
// Backwards-compatible: missing return values default to "denied" / "".
func (e *FilterEngine) callFilter(arg *lua.LTable) (bool, string, string) {
	if err := e.vm.CallByParam(lua.P{
		Fn:      e.filterFn,
		NRet:    3,
		Protect: true,
	}, arg); err != nil {
		vlog.Errorf("[Filter] Lua error: %v", err)
		return true, "", "" // fail-open on Lua errors
	}

	// Stack: [ret1, ret2, ret3] (top = ret3)
	ret3 := e.vm.Get(-1)
	ret2 := e.vm.Get(-2)
	ret1 := e.vm.Get(-3)
	e.vm.Pop(3)

	// Parse accepted (first return value)
	accepted := false
	switch v := ret1.(type) {
	case lua.LBool:
		accepted = bool(v)
	case *lua.LNilType:
		accepted = false
	default:
		accepted = true // fail-open on unexpected type
	}

	// Parse reason (second return value)
	reason := "denied"
	if s, ok := ret2.(lua.LString); ok && string(s) != "" {
		reason = string(s)
	}

	// Parse detail (third return value)
	detail := ""
	if s, ok := ret3.(lua.LString); ok {
		detail = string(s)
	}

	return accepted, reason, detail
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
