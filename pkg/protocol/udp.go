package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"vxlan-controller/pkg/crypto"
)

// UDP packet format: [1B msg_type][4B receiver_index][8B counter][NB encrypted_payload]
const UDPHeaderSize = 1 + 4 + 8

var ErrInvalidUDPPacket = errors.New("invalid UDP packet")

// WriteUDPPacket sends an encrypted UDP packet.
func WriteUDPPacket(conn net.PacketConn, addr net.Addr, session *crypto.Session, msgType MsgType, payload []byte) error {
	ciphertext, counter, err := session.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	packet := make([]byte, UDPHeaderSize+len(ciphertext))
	packet[0] = byte(msgType)
	binary.LittleEndian.PutUint32(packet[1:5], session.RemoteIndex)
	binary.LittleEndian.PutUint64(packet[5:13], counter)
	copy(packet[13:], ciphertext)

	_, err = conn.WriteTo(packet, addr)
	return err
}

// ParseUDPHeader extracts header fields without decrypting.
func ParseUDPHeader(data []byte) (msgType MsgType, receiverIndex uint32, counter uint64, ciphertext []byte, err error) {
	if len(data) < UDPHeaderSize {
		return 0, 0, 0, nil, ErrInvalidUDPPacket
	}

	msgType = MsgType(data[0])
	receiverIndex = binary.LittleEndian.Uint32(data[1:5])
	counter = binary.LittleEndian.Uint64(data[5:13])
	ciphertext = data[13:]
	return
}

// ReadUDPPacket decrypts a UDP packet using the session found by receiver_index.
func ReadUDPPacket(data []byte, findSession func(uint32) *crypto.Session) (MsgType, []byte, [32]byte, error) {
	msgType, receiverIndex, counter, ciphertext, err := ParseUDPHeader(data)
	if err != nil {
		return 0, nil, [32]byte{}, err
	}

	session := findSession(receiverIndex)
	if session == nil {
		return 0, nil, [32]byte{}, fmt.Errorf("no session for index %d", receiverIndex)
	}

	plaintext, err := session.Decrypt(ciphertext, counter)
	if err != nil {
		return 0, nil, [32]byte{}, fmt.Errorf("decrypt: %w", err)
	}

	return msgType, plaintext, session.PeerID, nil
}
