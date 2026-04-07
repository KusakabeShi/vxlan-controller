package filter

import (
	"net"
	"net/netip"

	lua "github.com/yuin/gopher-lua"

	"vxlan-controller/pkg/vlog"
)

// builtinModules maps module names to embedded Lua source code.
// These are available via require() without needing files on disk.
// If a file exists on disk with the same name, the disk version takes priority.
var builtinModules = map[string]string{
	"filter": BuiltinFilterModule,
}

// registerHelpers adds Go-implemented utility functions to the Lua VM.
func registerHelpers(vm *lua.LState) {
	vm.SetGlobal("ip_in_cidr", vm.NewFunction(luaIPInCIDR))
	vm.SetGlobal("log", vm.NewFunction(luaLog))
}

// ip_in_cidr(ip_string, cidr_string) -> bool
func luaIPInCIDR(L *lua.LState) int {
	ipStr := L.CheckString(1)
	cidrStr := L.CheckString(2)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		// Try as plain IP (treat as /32 or /128)
		_, _, err2 := net.ParseCIDR(cidrStr)
		if err2 != nil {
			L.Push(lua.LFalse)
			return 1
		}
	}
	L.Push(lua.LBool(prefix.Contains(addr)))
	return 1
}

// log(msg) -- writes to vlog at info level
func luaLog(L *lua.LState) int {
	msg := L.CheckString(1)
	vlog.Infof("[Lua] %s", msg)
	return 0
}

// BuiltinFilterModule provides preset filter functions.
// Usage in config:
//
//	local f = require("filter")
//	filter = f.filter_home_lan
const BuiltinFilterModule = `
local M = {}

-- Helper: build "src -> dst" flow string for reject detail
local function flow(pkt)
  return (pkt.src_ip or "") .. " -> " .. (pkt.dst_ip or "")
end

-- Helper: build descriptive reject reason from packet
local function describe(pkt)
  if pkt.ethertype == 0x0800 then
    local p = pkt.ip_protocol
    if p == 17 then return "ipv4:udp:" .. (pkt.dst_port or "?") end
    if p == 6  then return "ipv4:tcp:" .. (pkt.dst_port or "?") end
    if p == 2  then return "igmp" end
    if p == 1  then return "icmpv4:" .. (pkt.icmp_type or "?") end
    return "ipv4:proto:" .. p
  end
  if pkt.ethertype == 0x86dd then
    local p = pkt.ip_protocol
    if p == 17 then return "ipv6:udp:" .. (pkt.dst_port or "?") end
    if p == 6  then return "ipv6:tcp:" .. (pkt.dst_port or "?") end
    if p == 58 then return "icmpv6:" .. (pkt.icmpv6_type or "?") end
    return "ipv6:proto:" .. p
  end
  return "ether:0x" .. string.format("%04x", pkt.ethertype)
end

-- Export helpers so custom filters can reuse them
M.flow = flow
M.describe = describe

-- filter_allow_all: accept everything (no filtering)
function M.filter_allow_all(pkt)
  return true
end

-- filter_ix_lan: IX peering LAN — only ARP and IPv6 NS/NA
function M.filter_ix_lan(pkt)
  -- ARP
  if pkt.ethertype == 0x0806 then return true end
  -- IPv6 NS(135), NA(136)
  if pkt.ethertype == 0x86dd and pkt.icmpv6_type then
    local t = pkt.icmpv6_type
    if t == 135 or t == 136 then return true end
  end
  return false, describe(pkt), flow(pkt)
end

-- filter_home_lan: home/office LAN — ARP, ND, DHCP, mDNS, SSDP, LLMNR
function M.filter_home_lan(pkt)
  -- ARP
  if pkt.ethertype == 0x0806 then return true end
  -- IPv4
  if pkt.ethertype == 0x0800 and pkt.ip_protocol == 17 then
    local dp = pkt.dst_port
    if dp == 67 or dp == 68 then return true end    -- DHCP
    if dp == 5353 then return true end               -- mDNS
    if dp == 1900 then return true end               -- SSDP
    if dp == 5355 then return true end               -- LLMNR
  end
  -- IPv6 ICMPv6 ND: RS(133), RA(134), NS(135), NA(136)
  if pkt.ethertype == 0x86dd and pkt.icmpv6_type then
    local t = pkt.icmpv6_type
    if t >= 133 and t <= 136 then return true end
  end
  -- IPv6 UDP
  if pkt.ethertype == 0x86dd and pkt.ip_protocol == 17 then
    local dp = pkt.dst_port
    if dp == 546 or dp == 547 then return true end   -- DHCPv6
    if dp == 5353 then return true end               -- mDNS
    if dp == 1900 then return true end               -- SSDP
    if dp == 5355 then return true end               -- LLMNR
  end
  return false, describe(pkt), flow(pkt)
end

-- filter_isp: ISP/routing — ARP, NS/NA, OSPF, Babel
function M.filter_isp(pkt)
  -- ARP
  if pkt.ethertype == 0x0806 then return true end
  -- IPv4 OSPF (proto 89)
  if pkt.ethertype == 0x0800 and pkt.ip_protocol == 89 then return true end
  -- IPv4 Babel (UDP 6696)
  if pkt.ethertype == 0x0800 and pkt.ip_protocol == 17 and pkt.dst_port == 6696 then return true end
  -- IPv6 NS(135), NA(136)
  if pkt.ethertype == 0x86dd and pkt.icmpv6_type then
    local t = pkt.icmpv6_type
    if t == 135 or t == 136 then return true end
  end
  -- IPv6 OSPF (proto 89)
  if pkt.ethertype == 0x86dd and pkt.ip_protocol == 89 then return true end
  -- IPv6 Babel (UDP 6696)
  if pkt.ethertype == 0x86dd and pkt.ip_protocol == 17 and pkt.dst_port == 6696 then return true end
  return false, describe(pkt), flow(pkt)
end

return M
`
