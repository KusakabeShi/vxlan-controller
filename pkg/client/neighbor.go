package client

import (
	"log"
	"net"
	"net/netip"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	pb "vxlan-controller/proto"
)

// neighborWatchLoop monitors netlink neighbor events and sends incremental updates.
func (c *Client) neighborWatchLoop() {
	// Initial full dump
	c.dumpLocalState()

	// Subscribe to neighbor events
	neighCh := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.NeighSubscribe(neighCh, done); err != nil {
		log.Printf("[Client] netlink neighbor subscribe error: %v", err)
		return
	}

	for {
		select {
		case update, ok := <-neighCh:
			if !ok {
				return
			}
			if !c.isRelevantNeighEvent(update.Neigh) {
				continue
			}
			c.handleNeighEvent(update)
		case <-c.ctx.Done():
			return
		}
	}
}

// handleNeighEvent processes a single netlink neighbor event and sends an incremental update.
func (c *Client) handleNeighEvent(update netlink.NeighUpdate) {
	n := update.Neigh

	// Determine if this is an add or delete
	isDelete := false
	if update.Type == unix.RTM_DELNEIGH {
		isDelete = true
	} else if n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_NOARP) == 0 {
		// Not a usable state (e.g. NUD_FAILED, NUD_INCOMPLETE)
		isDelete = true
	}

	// Build route from event
	var rt *pb.Type2Route

	// Check if this is a bridge FDB entry (AF_BRIDGE) or a neighbor entry (AF_INET/AF_INET6)
	if n.Family == unix.AF_BRIDGE {
		// FDB entry — check if local
		if !c.isLocalFDBEntry(n) {
			return
		}
		rt = &pb.Type2Route{
			Mac:      n.HardwareAddr,
			IsDelete: isDelete,
		}
	} else {
		// ARP/NDP neighbor entry — check if on our bridge
		bridge, err := netlink.LinkByName(c.Config.BridgeName)
		if err != nil {
			return
		}
		if n.LinkIndex != bridge.Attrs().Index {
			return
		}
		if len(n.HardwareAddr) == 0 {
			return
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			return
		}
		rt = &pb.Type2Route{
			Mac:      n.HardwareAddr,
			Ip:       addrToBytes(ip),
			IsDelete: isDelete,
		}
	}

	// Update local state
	c.mu.Lock()
	localRT := types.Type2Route{MAC: rt.Mac}
	if len(rt.Ip) > 0 {
		if len(rt.Ip) == 4 {
			localRT.IP = netip.AddrFrom4([4]byte(rt.Ip))
		} else if len(rt.Ip) == 16 {
			localRT.IP = netip.AddrFrom16([16]byte(rt.Ip))
		}
	}
	if isDelete {
		c.LocalMACs = removeLocalRoute(c.LocalMACs, localRT)
	} else {
		c.LocalMACs = addLocalRoute(c.LocalMACs, localRT)
	}
	c.mu.Unlock()

	// Send incremental update via sendqueue
	macUpdate := &pb.MACUpdate{
		IsFull: false,
		Routes: []*pb.Type2Route{rt},
	}
	data, err := proto.Marshal(macUpdate)
	if err != nil {
		log.Printf("[Client] marshal MACUpdate error: %v", err)
		return
	}

	msg := clientEncodeMessage(protocol.MsgMACUpdate, data)
	c.mu.Lock()
	for _, cc := range c.Controllers {
		if !cc.MACsSynced {
			continue // sendloop will send full state anyway
		}
		select {
		case cc.SendQueue <- ClientQueueItem{State: msg}:
		default:
			cc.MACsSynced = false
		}
	}
	c.mu.Unlock()
}

func (c *Client) isRelevantNeighEvent(neigh netlink.Neigh) bool {
	link, err := netlink.LinkByIndex(neigh.LinkIndex)
	if err != nil {
		return false
	}

	if link.Attrs().Name == c.Config.BridgeName {
		return true
	}

	if link.Attrs().MasterIndex > 0 {
		master, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
		if err == nil && master.Attrs().Name == c.Config.BridgeName {
			return true
		}
	}

	return false
}

func (c *Client) dumpLocalState() {
	bridge, err := netlink.LinkByName(c.Config.BridgeName)
	if err != nil {
		log.Printf("[Client] bridge %s not found: %v", c.Config.BridgeName, err)
		return
	}
	bridgeIndex := bridge.Attrs().Index

	neighs, err := netlink.NeighList(0, unix.AF_BRIDGE)
	if err != nil {
		log.Printf("[Client] FDB dump error: %v", err)
		return
	}

	var routes []types.Type2Route
	for _, n := range neighs {
		if !c.entryBelongsToBridge(n, bridgeIndex) {
			continue
		}
		if !c.isLocalFDBEntry(n) {
			continue
		}
		rt := types.Type2Route{
			MAC: n.HardwareAddr,
		}
		routes = append(routes, rt)
	}

	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		neighEntries, err := netlink.NeighList(bridgeIndex, family)
		if err != nil {
			continue
		}
		for _, n := range neighEntries {
			if len(n.HardwareAddr) == 0 {
				continue
			}
			if n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT) == 0 {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			rt := types.Type2Route{
				MAC: n.HardwareAddr,
				IP:  ip,
			}
			routes = append(routes, rt)
		}
	}

	log.Printf("[Client] local state dump: found %d local routes", len(routes))

	c.mu.Lock()
	c.LocalMACs = routes
	// Trigger sendloop for each controller (MACsSynced=false ensures full send)
	for _, cc := range c.Controllers {
		select {
		case cc.SendQueue <- ClientQueueItem{}:
		default:
		}
	}
	c.mu.Unlock()
}

func (c *Client) entryBelongsToBridge(n netlink.Neigh, bridgeIndex int) bool {
	if n.LinkIndex == bridgeIndex {
		return true
	}
	link, err := netlink.LinkByIndex(n.LinkIndex)
	if err != nil {
		return false
	}
	return link.Attrs().MasterIndex == bridgeIndex
}

func (c *Client) isLocalFDBEntry(n netlink.Neigh) bool {
	if len(n.HardwareAddr) == 0 {
		return false
	}
	if n.HardwareAddr[0]&0x01 != 0 {
		return false
	}
	if len(n.IP) > 0 {
		return false
	}

	link, err := netlink.LinkByIndex(n.LinkIndex)
	if err != nil {
		return false
	}
	name := link.Attrs().Name

	for _, vd := range c.VxlanDevs {
		if name == vd.Name {
			return false
		}
	}
	if name == "tap-inject" {
		return false
	}

	return true
}

func addLocalRoute(routes []types.Type2Route, rt types.Type2Route) []types.Type2Route {
	for i, r := range routes {
		if macEqual(r.MAC, rt.MAC) && r.IP == rt.IP {
			routes[i] = rt
			return routes
		}
	}
	return append(routes, rt)
}

func removeLocalRoute(routes []types.Type2Route, rt types.Type2Route) []types.Type2Route {
	for i, r := range routes {
		if macEqual(r.MAC, rt.MAC) && r.IP == rt.IP {
			return append(routes[:i], routes[i+1:]...)
		}
	}
	return routes
}

func addrToBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
