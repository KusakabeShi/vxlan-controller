package filter

// DefaultMcastScript only allows ARP and IPv6 Neighbor Discovery (RS/RA/NS/NA).
const DefaultMcastScript = `
function filter(pkt)
  -- ARP
  if pkt.ethertype == 0x0806 then return true end
  -- IPv6 ND: RS(133), RA(134), NS(135), NA(136)
  if pkt.ethertype == 0x86dd and pkt.icmpv6_type then
    local t = pkt.icmpv6_type
    if t >= 133 and t <= 136 then return true end
  end
  return false
end
`

// DefaultRouteScript accepts all routes.
const DefaultRouteScript = `
function filter(route)
  return true
end
`

const (
	DefaultPerMACRate    = 64.0   // packets per second per source MAC
	DefaultPerClientRate = 1000.0 // packets per second per client total
)
