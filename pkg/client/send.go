package client

import (
	"net"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
)

func (c *Client) sendToAllControllers(msgType protocol.MsgType, payload []byte) {
	c.mu.Lock()
	ctrls := make([]*ControllerConn, 0, len(c.controllers))
	for _, ctrl := range c.controllers {
		ctrls = append(ctrls, ctrl)
	}
	c.mu.Unlock()

	for _, ctrl := range ctrls {
		_ = ctrl.Send(msgType, payload)
	}
}

func (ctrl *ControllerConn) pickSendConn() (conn net.Conn, sess *crypto.Session) {
	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	if ctrl.ActiveAF != "" {
		if ac := ctrl.AFConns[ctrl.ActiveAF]; ac != nil && ac.Connected && ac.TCPConn != nil && ac.Session != nil {
			return ac.TCPConn, ac.Session
		}
	}
	for _, ac := range ctrl.AFConns {
		if ac != nil && ac.Connected && ac.TCPConn != nil && ac.Session != nil {
			return ac.TCPConn, ac.Session
		}
	}
	return nil, nil
}
