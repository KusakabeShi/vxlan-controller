package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/vishvananda/netlink"

	"vxlan-controller/pkg/protocol"
	pb "vxlan-controller/proto"
)

func (c *Client) neighWatchLoop(ctx context.Context) {
	log := c.log.Named("neigh")
	bridgeLink, err := netlink.LinkByName(c.bridgeName)
	if err != nil {
		log.Error("bridge not found", zap.Error(err))
		return
	}
	bridgeIdx := bridgeLink.Attrs().Index

	ignored := make(map[int]struct{})
	for _, vx := range c.vxlanDevs {
		if vx == nil {
			continue
		}
		if l, err := netlink.LinkByName(vx.Name); err == nil {
			ignored[l.Attrs().Index] = struct{}{}
		}
	}
	if l, err := netlink.LinkByName(tapName); err == nil {
		ignored[l.Attrs().Index] = struct{}{}
	}

	updates := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	defer close(done)

	err = netlink.NeighSubscribeWithOptions(updates, done, netlink.NeighSubscribeOptions{
		ListExisting: true,
		ErrorCallback: func(e error) {
			log.Warn("neigh subscribe error", zap.Error(e))
		},
	})
	if err != nil {
		log.Error("neigh subscribe failed", zap.Error(err))
		return
	}

	pending := make(map[string]pb.RouteUpdate_Op)

	debounce := time.Duration(c.cfg.FDBDebounceMs) * time.Millisecond
	debounceMax := time.Duration(c.cfg.FDBDebounceMaxMs) * time.Millisecond

	flush := func() {
		if len(pending) == 0 {
			return
		}
		batch := &pb.RouteUpdateBatch{}
		c.mu.Lock()
		for k, op := range pending {
			entry := c.localRoutes[k]
			if entry == nil {
				continue
			}
			batch.Updates = append(batch.Updates, &pb.RouteUpdate{Op: op, Entry: entry})
		}
		c.mu.Unlock()
		pending = make(map[string]pb.RouteUpdate_Op)

		if len(batch.Updates) == 0 {
			return
		}
		log.Info("route update flush", zap.Int("updates", len(batch.Updates)))
		b, err := proto.Marshal(batch)
		if err != nil {
			return
		}
		c.sendToAllControllers(protocol.MsgRouteUpdate, b)
	}

	quiet := time.NewTimer(debounce)
	max := time.NewTimer(debounceMax)
	stopTimer := func(t *time.Timer) {
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}
	stopTimer(quiet)
	stopTimer(max)
	quietArmed := false
	maxArmed := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-quiet.C:
			quietArmed = false
			stopTimer(max)
			maxArmed = false
			flush()
		case <-max.C:
			maxArmed = false
			stopTimer(quiet)
			quietArmed = false
			flush()
		case u, ok := <-updates:
			if !ok {
				return
			}
			// Some netlink notifications may not populate MasterIndex reliably; fall back
			// to querying the link's master when needed.
			if u.MasterIndex != 0 && u.MasterIndex != bridgeIdx {
				continue
			}
			if u.MasterIndex == 0 {
				if l, err := netlink.LinkByIndex(u.LinkIndex); err == nil {
					if l.Attrs().MasterIndex != bridgeIdx {
						continue
					}
				} else {
					continue
				}
			}
			if _, ok := ignored[u.LinkIndex]; ok {
				continue
			}
			switch u.Type {
			case unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
			default:
				continue
			}

			// For AF_BRIDGE, we may get both FDB and (ext learned) neighbor entries.
			// Different kernel / netlink encodings may place the MAC in either HardwareAddr or IP (6 bytes).
			if u.Family == unix.AF_BRIDGE {
				var mac [6]byte
				haveMAC := false
				if len(u.HardwareAddr) == 6 {
					copy(mac[:], u.HardwareAddr)
					haveMAC = true
				} else if len(u.IP) == 6 {
					copy(mac[:], u.IP)
					haveMAC = true
				}
				if haveMAC {
					// FDB entry: MAC only (no IP).
					if len(u.IP) == 0 || len(u.IP) == 6 {
						k := routeKey(mac, nil)
						op := pb.RouteUpdate_OP_ADD
						if u.Type == unix.RTM_DELNEIGH {
							op = pb.RouteUpdate_OP_DEL
						}
						c.mu.Lock()
						if op == pb.RouteUpdate_OP_ADD {
							c.localRoutes[k] = &pb.MacIpEntry{Mac: mac[:], Ip: nil}
						} else {
							delete(c.localRoutes, k)
						}
						c.mu.Unlock()
						pending[k] = op
						if !quietArmed {
							quiet.Reset(debounce)
							quietArmed = true
						} else {
							stopTimer(quiet)
							quiet.Reset(debounce)
						}
						if !maxArmed {
							max.Reset(debounceMax)
							maxArmed = true
						}
						continue
					}
					// Neighbor entry: MAC + IP (used by neigh_suppress).
					if len(u.IP) == 4 || len(u.IP) == 16 {
						ip := net.IP(u.IP)
						k := routeKey(mac, ip)
						op := pb.RouteUpdate_OP_ADD
						if u.Type == unix.RTM_DELNEIGH {
							op = pb.RouteUpdate_OP_DEL
						}
						c.mu.Lock()
						if op == pb.RouteUpdate_OP_ADD {
							c.localRoutes[k] = &pb.MacIpEntry{Mac: mac[:], Ip: []byte(ip)}
						} else {
							delete(c.localRoutes, k)
						}
						c.mu.Unlock()
						pending[k] = op
						if !quietArmed {
							quiet.Reset(debounce)
							quietArmed = true
						} else {
							stopTimer(quiet)
							quiet.Reset(debounce)
						}
						if !maxArmed {
							max.Reset(debounceMax)
							maxArmed = true
						}
						continue
					}
				}
			}

			// Regular neighbor table on the bridge ports.
			if (len(u.IP) == 4 || len(u.IP) == 16) && len(u.HardwareAddr) == 6 {
				mac := [6]byte{}
				copy(mac[:], u.HardwareAddr)
				k := routeKey(mac, net.IP(u.IP))
				op := pb.RouteUpdate_OP_ADD
				if u.Type == unix.RTM_DELNEIGH {
					op = pb.RouteUpdate_OP_DEL
				}
				c.mu.Lock()
				if op == pb.RouteUpdate_OP_ADD {
					c.localRoutes[k] = &pb.MacIpEntry{Mac: mac[:], Ip: []byte(net.IP(u.IP))}
				} else {
					delete(c.localRoutes, k)
				}
				c.mu.Unlock()
				pending[k] = op
				if !quietArmed {
					quiet.Reset(debounce)
					quietArmed = true
				} else {
					stopTimer(quiet)
					quiet.Reset(debounce)
				}
				if !maxArmed {
					max.Reset(debounceMax)
					maxArmed = true
				}
			}
		}
	}
}

func routeKey(mac [6]byte, ip net.IP) string {
	if ip == nil || len(ip) == 0 {
		return fmt.Sprintf("%x|", mac)
	}
	return fmt.Sprintf("%x|%s", mac, ip.String())
}
