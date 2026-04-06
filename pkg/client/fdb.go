package client

import (
	"log"
	"net"

	"vxlan-controller/pkg/types"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fdbKey struct {
	MAC string
}

type fdbEntry struct {
	DevName string
	DstIP   net.IP
}

// fdbReconcileLoop watches for RouteMatrix/RouteTable changes and updates kernel FDB.
func (c *Client) fdbReconcileLoop() {
	// Wait for init
	select {
	case <-c.initDone:
	case <-c.ctx.Done():
		return
	}

	for {
		select {
		case <-c.fdbNotifyCh:
			c.reconcileFDB()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) reconcileFDB() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.AuthorityCtrl == nil {
		return
	}

	cc, ok := c.Controllers[*c.AuthorityCtrl]
	if !ok || cc.State == nil {
		return
	}

	view := cc.State

	log.Printf("[Client] FDB reconcile: RouteMatrix=%d rows, RouteTable=%d entries, Clients=%d",
		len(view.RouteMatrix), len(view.RouteTable), len(view.Clients))

	desiredFDB := make(map[fdbKey]fdbEntry)

	for _, rtEntry := range view.RouteTable {
		// Select owner: the one with lowest latency in LatencyMatrix
		ownerClient := c.selectRouteOwner(rtEntry, view)
		if ownerClient == nil {
			continue
		}

		// Lookup route from me to the owner
		myRoutes, ok := view.RouteMatrix[c.ClientID]
		if !ok {
			continue
		}
		routeEntry, ok := myRoutes[*ownerClient]
		if !ok {
			continue // unreachable
		}

		// Find the nexthop's endpoint for the chosen AF
		nextHopInfo, ok := view.Clients[routeEntry.NextHop]
		if !ok {
			continue
		}
		ep, ok := nextHopInfo.Endpoints[routeEntry.AF]
		if !ok {
			continue
		}

		// Find the vxlan device for this AF
		vxlanDev, ok := c.VxlanDevs[routeEntry.AF]
		if !ok {
			continue
		}

		key := fdbKey{MAC: rtEntry.MAC.String()}
		desiredFDB[key] = fdbEntry{
			DevName: vxlanDev.Name,
			DstIP:   ep.IP.AsSlice(),
		}
	}

	// Also add FDB entries for routes from RouteMatrix that have direct MAC entries
	// from remote clients
	for clientID, ci := range view.Clients {
		if clientID == c.ClientID {
			continue
		}
		myRoutes, ok := view.RouteMatrix[c.ClientID]
		if !ok {
			continue
		}
		routeEntry, ok := myRoutes[clientID]
		if !ok {
			continue
		}

		nextHopInfo, ok := view.Clients[routeEntry.NextHop]
		if !ok {
			continue
		}
		ep, ok := nextHopInfo.Endpoints[routeEntry.AF]
		if !ok {
			continue
		}

		vxlanDev, ok := c.VxlanDevs[routeEntry.AF]
		if !ok {
			continue
		}

		for _, route := range ci.Routes {
			key := fdbKey{MAC: route.MAC.String()}
			if _, exists := desiredFDB[key]; !exists {
				desiredFDB[key] = fdbEntry{
					DevName: vxlanDev.Name,
					DstIP:   ep.IP.AsSlice(),
				}
			}
		}
	}

	// Diff and apply
	// Delete entries no longer needed
	for key, entry := range c.CurrentFDB {
		desired, ok := desiredFDB[key]
		if !ok || desired.DevName != entry.DevName || !desired.DstIP.Equal(entry.DstIP) {
			c.deleteFDBEntry(key, entry)
		}
	}

	// Add/update entries
	for key, entry := range desiredFDB {
		current, ok := c.CurrentFDB[key]
		if !ok || current.DevName != entry.DevName || !current.DstIP.Equal(entry.DstIP) {
			if ok {
				c.deleteFDBEntry(key, current)
			}
			c.addFDBEntry(key, entry)
		}
	}

	c.CurrentFDB = desiredFDB
}

func (c *Client) selectRouteOwner(rtEntry *types.RouteTableEntry, view *ControllerView) *types.ClientID {
	var bestClient *types.ClientID

	myRoutes := view.RouteMatrix[c.ClientID]

	for clientID := range rtEntry.Owners {
		if clientID == c.ClientID {
			// Local owner - always best
			id := clientID
			return &id
		}

		// Check if reachable via RouteMatrix
		if myRoutes != nil {
			if _, ok := myRoutes[clientID]; ok {
				id := clientID
				if bestClient == nil {
					bestClient = &id
				}
			}
		}
	}

	// If no reachable owner found, just pick the first one
	if bestClient == nil {
		for clientID := range rtEntry.Owners {
			id := clientID
			bestClient = &id
			break
		}
	}

	return bestClient
}

func (c *Client) addFDBEntry(key fdbKey, entry fdbEntry) {
	mac, err := net.ParseMAC(key.MAC)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(entry.DevName)
	if err != nil {
		log.Printf("[Client] FDB add: link %s not found: %v", entry.DevName, err)
		return
	}

	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		HardwareAddr: mac,
		IP:           entry.DstIP,
	}

	if err := netlink.NeighAppend(neigh); err != nil {
		log.Printf("[Client] FDB append %s -> %s via %s: %v", key.MAC, entry.DstIP, entry.DevName, err)
	} else {
		log.Printf("[Client] FDB added %s -> %s via %s", key.MAC, entry.DstIP, entry.DevName)
	}
}

func (c *Client) deleteFDBEntry(key fdbKey, entry fdbEntry) {
	mac, err := net.ParseMAC(key.MAC)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(entry.DevName)
	if err != nil {
		return
	}

	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		HardwareAddr: mac,
		IP:           entry.DstIP,
	}

	netlink.NeighDel(neigh)
}

func (c *Client) cleanupFDB() {
	for key, entry := range c.CurrentFDB {
		c.deleteFDBEntry(key, entry)
	}
	c.CurrentFDB = make(map[fdbKey]fdbEntry)
}

func (c *Client) notifyFDB() {
	select {
	case c.fdbNotifyCh <- struct{}{}:
	default:
	}
}
