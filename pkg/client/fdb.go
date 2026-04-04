package client

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"time"

	"go.uber.org/zap"
	pb "vxlan-controller/proto"

	"vxlan-controller/pkg/types"
)

type fdbKey struct {
	mac [6]byte
}

type fdbEntry struct {
	dev string
	dst netip.Addr
}

type neighKey struct {
	ip netip.Addr
}

func (c *Client) fdbReconcileLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.fdbNotifyCh:
		}
		c.reconcileOnce()
	}
}

func (c *Client) reconcileOnce() {
	c.mu.Lock()
	auth := c.authority
	var view *ControllerView
	if auth != nil {
		ctrl := c.controllers[*auth]
		if ctrl != nil {
			ctrl.mu.Lock()
			view = ctrl.View
			ctrl.mu.Unlock()
		}
	}
	myID := c.clientID
	neighSuppress := c.cfg.NeighSuppress
	c.mu.Unlock()
	if view == nil {
		return
	}

	desiredFDB := make(map[fdbKey]fdbEntry)
	desiredNeigh := make(map[neighKey]struct{})
	macPresent := make(map[fdbKey]struct{})

	for _, rte := range view.RouteTable {
		if rte == nil || len(rte.Mac) != 6 {
			continue
		}
		var mac [6]byte
		copy(mac[:], rte.Mac)
		if mac[0]&1 == 1 {
			continue // skip multicast/broadcast
		}
		macPresent[fdbKey{mac: mac}] = struct{}{}

		owner := pickOwner(myID, rte, view)
		if owner == (types.ClientID{}) {
			continue
		}
		re := view.Route[myID][owner]
		if re == nil || len(re.NexthopClientId) != 32 || re.AfName == "" {
			continue
		}
		var nexthop types.ClientID
		copy(nexthop[:], re.NexthopClientId)
		af := types.AFName(re.AfName)
		vx := c.vxlanDevs[af]
		if vx == nil {
			continue
		}
		nhIP, err := nexthopIP(view, nexthop, af)
		if err != nil || !nhIP.IsValid() {
			continue
		}
		desiredFDB[fdbKey{mac: mac}] = fdbEntry{dev: vx.Name, dst: nhIP}

		if neighSuppress && len(rte.Ip) > 0 {
			ip, err := types.BytesToNetIP(rte.Ip)
			if err == nil && ip.IsValid() {
				desiredNeigh[neighKey{ip: ip}] = struct{}{}
				_ = c.neighReplace(ip, mac)
			}
		}
	}

	// Apply FDB diff.
	for k, want := range desiredFDB {
		cur, ok := c.currentFDB[k]
		if ok && cur.dev == want.dev && cur.dst == want.dst {
			continue
		}
		if err := c.fdbReplace(k.mac, want.dev, want.dst); err != nil {
			c.log.Warn("fdb replace failed", zap.String("dev", want.dev), zap.Error(err))
		} else {
			c.currentFDB[k] = want
			c.log.Debug("fdb updated",
				zap.String("mac", fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", k.mac[0], k.mac[1], k.mac[2], k.mac[3], k.mac[4], k.mac[5])),
				zap.String("dev", want.dev),
				zap.String("dst", want.dst.String()),
			)
		}
	}
	for k, cur := range c.currentFDB {
		if _, ok := desiredFDB[k]; ok {
			continue
		}
		// If the controller still reports this MAC in the route table but the current
		// snapshot does not contain a usable next-hop (e.g. transient topology gaps
		// or controller failover), keep the existing FDB entry to preserve forwarding.
		if _, stillPresent := macPresent[k]; stillPresent {
			continue
		}
		_ = c.fdbDel(k.mac, cur.dev)
		delete(c.currentFDB, k)
		c.log.Debug("fdb deleted",
			zap.String("mac", fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", k.mac[0], k.mac[1], k.mac[2], k.mac[3], k.mac[4], k.mac[5])),
			zap.String("dev", cur.dev),
		)
	}

	// Apply neighbor deletes.
	for k := range c.currentNeigh {
		if _, ok := desiredNeigh[k]; ok {
			continue
		}
		_ = c.neighDel(k.ip)
		delete(c.currentNeigh, k)
	}
	for k := range desiredNeigh {
		c.currentNeigh[k] = struct{}{}
	}
}

func pickOwner(me types.ClientID, rte *pb.RouteTableEntry, view *ControllerView) types.ClientID {
	best := types.ClientID{}
	bestLat := math.Inf(1)
	now := time.Now()
	for _, o := range rte.GetOwners() {
		if o == nil || len(o.ClientId) != 32 {
			continue
		}
		if o.ExpireUnixNs > 0 && time.Unix(0, o.ExpireUnixNs).Before(now) {
			continue
		}
		var id types.ClientID
		copy(id[:], o.ClientId)
		lat := math.Inf(1)
		if row := view.Latency[me]; row != nil {
			if e := row[id]; e != nil {
				lat = e.LatencyMs
			}
		}
		if lat < bestLat {
			bestLat = lat
			best = id
		}
	}
	if best != (types.ClientID{}) {
		return best
	}
	// Fallback deterministic: first owner.
	for _, o := range rte.GetOwners() {
		if o == nil || len(o.ClientId) != 32 {
			continue
		}
		var id types.ClientID
		copy(id[:], o.ClientId)
		return id
	}
	return types.ClientID{}
}

func nexthopIP(view *ControllerView, nexthop types.ClientID, af types.AFName) (netip.Addr, error) {
	ci := view.ClientsByID[nexthop]
	if ci == nil {
		return netip.Addr{}, fmt.Errorf("unknown client")
	}
	for _, ep := range ci.GetEndpoints() {
		if ep == nil || types.AFName(ep.GetAfName()) != af {
			continue
		}
		return types.BytesToNetIP(ep.GetIp())
	}
	return netip.Addr{}, fmt.Errorf("missing endpoint")
}

func (c *Client) fdbReplace(mac [6]byte, dev string, dst netip.Addr) error {
	m := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	_, err := run("bridge", "fdb", "replace", m, "dev", dev, "dst", dst.String())
	return err
}

func (c *Client) fdbDel(mac [6]byte, dev string) error {
	m := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	_, err := run("bridge", "fdb", "del", m, "dev", dev)
	return err
}

func (c *Client) neighReplace(ip netip.Addr, mac [6]byte) error {
	m := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	args := []string{"neigh", "replace", ip.String(), "lladdr", m, "nud", "permanent", "dev", c.bridgeName}
	_, err := run("ip", args...)
	return err
}

func (c *Client) neighDel(ip netip.Addr) error {
	_, err := run("ip", "neigh", "del", ip.String(), "dev", c.bridgeName)
	return err
}
