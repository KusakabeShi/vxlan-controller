package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
	pb "vxlan-controller/proto"
)

func (c *Client) tcpConnLoop(
	ctx context.Context,
	ctrlID types.ControllerID,
	afName types.AFName,
	remote netip.AddrPort,
	ctrlPubKey [32]byte,
) {
	log := c.log.Named("tcp").With(zap.String("controller", types.ClientID(ctrlID).String()), zap.String("af", string(afName)))
	backoff := 200 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read current bind settings (may change via API).
		c.mu.Lock()
		afCfg := c.cfg.AFSettings[afName]
		curBind := netip.Addr{}
		var curPort uint16
		if afCfg != nil {
			curBind = afCfg.BindAddr.Addr
			curPort = afCfg.CommunicationPort
		}
		c.mu.Unlock()
		if !curBind.IsValid() || curPort == 0 {
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}

		conn, sess, err := c.dialAndHandshake(ctx, curBind, curPort, remote, ctrlPubKey)
		if err != nil {
			log.Warn("connect failed", zap.Error(err))
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 200 * time.Millisecond

		rt := c.afRuntime[afName]
		if rt == nil {
			_ = conn.Close()
			return
		}
		rt.RegisterCommSession(sess)

		c.mu.Lock()
		ctrl := c.controllers[ctrlID]
		if ctrl == nil {
			ctrl = &ControllerConn{ControllerID: ctrlID, AFConns: make(map[types.AFName]*ClientAFConn)}
			c.controllers[ctrlID] = ctrl
		}
		ctrl.mu.Lock()
		ctrl.AFConns[afName] = &ClientAFConn{AF: afName, TCPConn: conn, Session: sess, Connected: true}
		ctrl.mu.Unlock()
		c.mu.Unlock()

		if err := c.sendClientRegisterOnConn(conn, sess); err != nil {
			log.Warn("send register failed", zap.Error(err))
			rt.UnregisterCommSession(sess.LocalIndex)
			_ = conn.Close()
			continue
		}
		_ = c.sendFullLocalStateToController(ctrlID)

		err = c.tcpRecvLoop(ctx, ctrlID, afName, conn, sess)

		rt.UnregisterCommSession(sess.LocalIndex)
		_ = conn.Close()

		c.mu.Lock()
		if ctrl := c.controllers[ctrlID]; ctrl != nil {
			ctrl.mu.Lock()
			if ac := ctrl.AFConns[afName]; ac != nil {
				ac.Connected = false
			}
			ctrl.Synced = false
			ctrl.mu.Unlock()
		}
		c.mu.Unlock()
		selectNonBlocking(c.authNotifyCh)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Info("disconnected", zap.Error(err))
		}
	}
}

func (c *Client) dialAndHandshake(ctx context.Context, localBind netip.Addr, localPort uint16, remote netip.AddrPort, ctrlPub [32]byte) (net.Conn, *crypto.Session, error) {
	d := net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: &net.TCPAddr{IP: localBind.AsSlice(), Port: int(localPort)},
		Control: func(network, address string, cfd syscall.RawConn) error {
			var ctrlErr error
			_ = cfd.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				// Best effort: allow multiple outbound dials from the same local port.
				const soReusePort = 15
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			})
			return ctrlErr
		},
	}
	conn, err := d.DialContext(ctx, "tcp", remote.String())
	if err != nil {
		return nil, nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		// We use a fixed local port (communication_port). When the controller restarts,
		// reconnecting with the same 4-tuple can be blocked by TIME_WAIT. Using linger=0
		// avoids TIME_WAIT on close and makes fast reconnects reliable.
		_ = tcp.SetLinger(0)
	}

	// Bound the handshake so a misbehaving peer can't stall the reconnect loop.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	initPayload, st, err := crypto.HandshakeInitiate(c.privateKey, ctrlPub, c.Now())
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if err := protocol.WriteTCPMessage(conn, nil, protocol.MsgHandshakeInit, initPayload); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	mt, respPayload, err := protocol.ReadTCPMessage(conn, nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if mt != protocol.MsgHandshakeResp {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("unexpected handshake resp type %d", mt)
	}
	sess, err := crypto.HandshakeFinalize(st, respPayload)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, sess, nil
}

func (c *Client) sendClientRegisterOnConn(conn net.Conn, sess *crypto.Session) error {
	if conn == nil || sess == nil {
		return errors.New("nil conn/session")
	}
	reg := &pb.ClientRegister{ClientId: c.clientID.Bytes()}
	for name, af := range c.cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		reg.Afs = append(reg.Afs, &pb.ClientRegisterAF{
			AfName:       string(name),
			ProbePort:    uint32(af.ProbePort),
			VxlanDstport: uint32(af.VxlanDstPort),
			Priority:     af.Priority,
		})
	}
	b, err := proto.Marshal(reg)
	if err != nil {
		return err
	}
	return protocol.WriteTCPMessage(conn, sess, protocol.MsgClientRegister, b)
}

func (c *Client) tcpRecvLoop(ctx context.Context, ctrlID types.ControllerID, afName types.AFName, conn net.Conn, sess *crypto.Session) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		mt, plain, err := protocol.ReadTCPMessage(conn, sess)
		if err != nil {
			return err
		}
		switch mt {
		case protocol.MsgControllerState:
			var st pb.ControllerState
			if err := proto.Unmarshal(plain, &st); err != nil {
				continue
			}
			view, err := BuildControllerView(&st)
			if err != nil {
				continue
			}
			c.mu.Lock()
			ctrl := c.controllers[ctrlID]
			if ctrl != nil {
				ctrl.mu.Lock()
				ctrl.View = view
				ctrl.Synced = true
				ctrl.ActiveAF = afName
				ctrl.mu.Unlock()
			}
			c.mu.Unlock()
			c.log.Info("controller state synced",
				zap.String("controller", types.ClientID(ctrlID).String()),
				zap.String("af", string(afName)),
				zap.Uint32("client_count", st.GetClientCount()),
			)
			// Ensure every controller eventually learns our full local state, even if it
			// missed early RouteUpdate deltas during reconnect or startup.
			go func() { _ = c.sendFullLocalStateToController(ctrlID) }()
			selectNonBlocking(c.authNotifyCh)
			selectNonBlocking(c.fdbNotifyCh)
		case protocol.MsgControllerStateUpdate:
			var up pb.ControllerStateUpdate
			if err := proto.Unmarshal(plain, &up); err != nil {
				continue
			}
			if up.GetState() == nil {
				continue
			}
			view, err := BuildControllerView(up.GetState())
			if err != nil {
				continue
			}
			c.mu.Lock()
			ctrl := c.controllers[ctrlID]
			if ctrl != nil {
				ctrl.mu.Lock()
				ctrl.View = view
				ctrl.Synced = true
				ctrl.mu.Unlock()
			}
			c.mu.Unlock()
			c.log.Info("controller state updated",
				zap.String("controller", types.ClientID(ctrlID).String()),
				zap.String("af", string(afName)),
				zap.Uint32("client_count", up.GetState().GetClientCount()),
			)
			selectNonBlocking(c.fdbNotifyCh)
		case protocol.MsgControllerProbeRequest:
			var req pb.ControllerProbeRequest
			if err := proto.Unmarshal(plain, &req); err != nil {
				continue
			}
			go c.handleProbeRequest(ctrlID, &req)
		default:
		}
	}
}

func selectNonBlocking(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
