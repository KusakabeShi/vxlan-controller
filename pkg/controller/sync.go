package controller

import (
	"log"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"

	pb "vxlan-controller/proto"
)

// pushDelta sends an incremental update to all synced clients.
// Must be called with c.mu held.
func (c *Controller) pushDelta(update *pb.ControllerStateUpdate) {
	data, err := proto.Marshal(update)
	if err != nil {
		log.Printf("[Controller] failed to marshal ControllerStateUpdate: %v", err)
		return
	}

	msg := encodeMessage(protocol.MsgControllerStateUpdate, data)
	for _, cc := range c.clients {
		if !cc.Synced {
			continue
		}
		select {
		case cc.SendQueue <- QueueItem{State: msg}:
		default:
			log.Printf("[Controller] send queue full for client %s, marking unsynced", cc.ClientID.Hex())
			cc.Synced = false
			// No drain — sendloop will overwrite State with full on next dequeue
		}
	}
}

// encodeMessage prepends the msg_type byte to payload.
func encodeMessage(msgType protocol.MsgType, payload []byte) []byte {
	msg := make([]byte, 1+len(payload))
	msg[0] = byte(msgType)
	copy(msg[1:], payload)
	return msg
}

// getFullStateEncoded returns the full state snapshot as an encoded message.
// Must be called with c.mu held (at least RLock).
func (c *Controller) getFullStateEncoded() []byte {
	snapshot := c.State.Snapshot(c.ControllerID)
	data, err := proto.Marshal(snapshot)
	if err != nil {
		log.Printf("[Controller] failed to marshal ControllerState: %v", err)
		return nil
	}
	return encodeMessage(protocol.MsgControllerState, data)
}
