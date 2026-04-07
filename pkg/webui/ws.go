package webui

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"vxlan-controller/pkg/vlog"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // allow any origin (reverse proxy)
}

type wsConn struct {
	conn *websocket.Conn
	send chan []byte
}

func (c *wsConn) close() {
	c.conn.Close()
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		vlog.Warnf("[WebUI] ws upgrade failed: %v", err)
		return
	}

	c := &wsConn{
		conn: conn,
		send: make(chan []byte, 8),
	}
	s.hub.register(c)

	// Send initial state immediately
	state := s.provider()
	if data, err := json.Marshal(state); err == nil {
		conn.WriteMessage(websocket.TextMessage, data)
	}

	// Writer goroutine
	go func() {
		defer func() {
			s.hub.unregister(c)
			conn.Close()
		}()
		for msg := range c.send {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	// Reader goroutine (just drain, handle close)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			close(c.send)
			return
		}
	}
}
