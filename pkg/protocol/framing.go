package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"vxlan-controller/pkg/crypto"
)

// TCP message format: [4B length][1B msg_type][NB encrypted_payload]
// length = 1 + N (msg_type + encrypted_payload)

const (
	MaxTCPMessageSize = 4 * 1024 * 1024 // 4MB max
	TCPHeaderSize     = 4               // length field
)

var (
	ErrMessageTooLarge = errors.New("message too large")
	ErrMessageTooSmall = errors.New("message too small")
)

// WriteTCPRaw writes a raw (unencrypted) TCP message (for handshake).
func WriteTCPRaw(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	if length > MaxTCPMessageSize {
		return ErrMessageTooLarge
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// ReadTCPRaw reads a raw (unencrypted) TCP message (for handshake).
func ReadTCPRaw(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)
	if length > MaxTCPMessageSize {
		return nil, ErrMessageTooLarge
	}
	if length == 0 {
		return nil, ErrMessageTooSmall
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// WriteTCPMessage writes an encrypted TCP message.
func WriteTCPMessage(conn net.Conn, session *crypto.Session, msgType MsgType, payload []byte) error {
	ciphertext, counter, err := session.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Build: [1B msg_type][8B counter][NB ciphertext]
	inner := make([]byte, 1+8+len(ciphertext))
	inner[0] = byte(msgType)
	binary.LittleEndian.PutUint64(inner[1:9], counter)
	copy(inner[9:], ciphertext)

	return WriteTCPRaw(conn, inner)
}

// ReadTCPMessage reads an encrypted TCP message.
func ReadTCPMessage(conn net.Conn, session *crypto.Session) (MsgType, []byte, error) {
	data, err := ReadTCPRaw(conn)
	if err != nil {
		return 0, nil, err
	}

	if len(data) < 9 {
		return 0, nil, ErrMessageTooSmall
	}

	msgType := MsgType(data[0])
	counter := binary.LittleEndian.Uint64(data[1:9])
	ciphertext := data[9:]

	plaintext, err := session.Decrypt(ciphertext, counter)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt: %w", err)
	}

	return msgType, plaintext, nil
}
