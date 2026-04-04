package client

import (
	"context"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
	pb "vxlan-controller/proto"
)

func (c *Client) tapReadLoop(ctx context.Context) {
	buf := make([]byte, 64*1024)
	var count int
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastCtrl types.ControllerID
	var lastAF types.AFName
	var haveLast bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			count = 0
		default:
		}
		n, err := c.tap.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		if n < 14 {
			continue
		}
		frame := make([]byte, n)
		copy(frame, buf[:n])

		// multicast/broadcast only: dst mac LSB=1
		if (frame[0] & 0x01) == 0 {
			continue
		}

		if c.cfg.BroadcastPPSLimit > 0 {
			if count >= c.cfg.BroadcastPPSLimit {
				continue
			}
			count++
		}

		// Prefer the authority controller, but fall back to any reachable controller so
		// broadcast relay keeps working during authority re-election / controller restarts.
		type cand struct {
			ctrl *ControllerConn
			af   types.AFName
			sess *crypto.Session
			dst  netip.AddrPort
		}
		var picked *cand

		c.mu.Lock()
		auth := c.authority
		ctrls := make([]*ControllerConn, 0, len(c.controllers))
		for _, cc := range c.controllers {
			ctrls = append(ctrls, cc)
		}
		c.mu.Unlock()

		buildCand := func(ctrl *ControllerConn) *cand {
			if ctrl == nil {
				return nil
			}
			af, sess := ctrl.pickConnectedAFSession()
			if af == "" || sess == nil {
				return nil
			}
			rt := c.afRuntime[af]
			if rt == nil || rt.CommUDP == nil {
				return nil
			}
			c.mu.Lock()
			dst, ok := c.controllerEndpoints[ctrl.ControllerID][af]
			c.mu.Unlock()
			if !ok || !dst.IsValid() {
				return nil
			}
			return &cand{ctrl: ctrl, af: af, sess: sess, dst: dst}
		}

		// Try authority first.
		if auth != nil {
			c.mu.Lock()
			authorityCtrl := c.controllers[*auth]
			c.mu.Unlock()
			picked = buildCand(authorityCtrl)
		}
		// Otherwise pick deterministically among remaining candidates.
		if picked == nil {
			for _, cc := range ctrls {
				cd := buildCand(cc)
				if cd == nil {
					continue
				}
				if picked == nil || types.CompareClientID(types.ClientID(cd.ctrl.ControllerID), types.ClientID(picked.ctrl.ControllerID)) < 0 {
					picked = cd
				}
			}
		}

		if picked == nil || picked.ctrl == nil || picked.sess == nil || picked.af == "" {
			continue
		}
		if !haveLast || picked.ctrl.ControllerID != lastCtrl || picked.af != lastAF {
			c.log.Info("broadcast relay controller selected",
				zap.String("controller", types.ClientID(picked.ctrl.ControllerID).String()),
				zap.String("af", string(picked.af)),
			)
			lastCtrl = picked.ctrl.ControllerID
			lastAF = picked.af
			haveLast = true
		}
		rt := c.afRuntime[picked.af]
		if rt == nil {
			continue
		}

		msg := &pb.MulticastForward{SourceClientId: c.clientID.Bytes(), Frame: frame}
		b, err := proto.Marshal(msg)
		if err != nil {
			continue
		}
		_ = protocol.WriteUDPPacket(rt.CommUDP, net.UDPAddrFromAddrPort(picked.dst), picked.sess, protocol.MsgMulticastForward, b)
	}
}

func (c *Client) tapWriteLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-c.tapInjectCh:
			if len(frame) == 0 {
				continue
			}
			_, _ = c.tap.Write(frame)
		}
	}
}
