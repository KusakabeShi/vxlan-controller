package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/types"
)

// UDP format:
// [1B msg_type][4B receiver_index LE][8B counter LE][NB encrypted payload]

func WriteUDPPacket(conn net.PacketConn, addr net.Addr, session *crypto.Session, msgType MsgType, payload []byte) error {
	if session == nil {
		return errors.New("nil session for udp packet")
	}
	counter, err := session.NextUDPCounter()
	if err != nil {
		return err
	}
	enc, err := session.EncryptUDP(counter, payload, []byte{byte(msgType)})
	if err != nil {
		return err
	}
	buf := make([]byte, 1+4+8+len(enc))
	buf[0] = byte(msgType)
	binary.LittleEndian.PutUint32(buf[1:5], session.RemoteIndex)
	binary.LittleEndian.PutUint64(buf[5:13], counter)
	copy(buf[13:], enc)
	_, err = conn.WriteTo(buf, addr)
	return err
}

func ReadUDPPacket(data []byte, findSession func(uint32) *crypto.Session) (msgType MsgType, payload []byte, peerID types.ClientID, err error) {
	if len(data) < 1+4+8+16 {
		return 0, nil, peerID, fmt.Errorf("udp packet too short: %d", len(data))
	}
	msgType = MsgType(data[0])
	receiverIndex := binary.LittleEndian.Uint32(data[1:5])
	counter := binary.LittleEndian.Uint64(data[5:13])
	ciphertext := data[13:]

	sess := findSession(receiverIndex)
	if sess == nil {
		return 0, nil, peerID, fmt.Errorf("unknown receiver_index: %d", receiverIndex)
	}
	plain, err := sess.DecryptUDP(counter, ciphertext, []byte{byte(msgType)})
	if err != nil {
		return 0, nil, peerID, err
	}
	return msgType, plain, sess.PeerID, nil
}
