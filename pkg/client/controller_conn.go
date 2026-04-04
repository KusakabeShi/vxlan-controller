package client

import (
	"net"
	"sync"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
)

type ClientAFConn struct {
	AF      types.AFName
	TCPConn net.Conn
	Session *crypto.Session
	// The runtime UDP socket is stored in AFRuntime.
	Connected bool
}

type ControllerConn struct {
	ControllerID types.ControllerID
	AFConns      map[types.AFName]*ClientAFConn
	ActiveAF     types.AFName

	mu     sync.Mutex
	sendMu sync.Mutex
	Synced bool
	View   *ControllerView
}

func (c *ControllerConn) Send(msgType protocol.MsgType, payload []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	conn, sess := c.pickSendConn()
	if conn == nil || sess == nil {
		return nil
	}
	return protocol.WriteTCPMessage(conn, sess, msgType, payload)
}

// pickConnectedAFSession returns an AF + session suitable for UDP broadcast relay.
// It prefers the controller's current ActiveAF if usable, otherwise falls back to
// any connected AF deterministically (lexicographically smallest AF name).
func (c *ControllerConn) pickConnectedAFSession() (af types.AFName, sess *crypto.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ActiveAF != "" {
		if ac := c.AFConns[c.ActiveAF]; ac != nil && ac.Connected && ac.Session != nil {
			return c.ActiveAF, ac.Session
		}
	}
	var bestAF types.AFName
	var bestSess *crypto.Session
	for a, ac := range c.AFConns {
		if ac == nil || !ac.Connected || ac.Session == nil {
			continue
		}
		if bestSess == nil || string(a) < string(bestAF) {
			bestAF = a
			bestSess = ac.Session
		}
	}
	return bestAF, bestSess
}
