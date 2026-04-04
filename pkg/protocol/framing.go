package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"vxlan-controller/pkg/crypto"
)

func WriteTCPMessage(conn net.Conn, session *crypto.Session, msgType MsgType, payload []byte) error {
	var body []byte
	if msgType == MsgHandshakeInit || msgType == MsgHandshakeResp {
		body = payload
	} else {
		if session == nil {
			return errors.New("nil session for encrypted tcp message")
		}
		enc, _, err := session.EncryptNextTCP(payload, []byte{byte(msgType)})
		if err != nil {
			return err
		}
		body = enc
	}

	if len(body) > 16*1024*1024 {
		return fmt.Errorf("tcp message too large: %d", len(body))
	}
	length := uint32(1 + len(body))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], length)
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{byte(msgType)}); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

func ReadTCPMessage(conn net.Conn, session *crypto.Session) (MsgType, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 || length > 16*1024*1024 {
		return 0, nil, fmt.Errorf("invalid tcp length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, nil, err
	}
	msgType := MsgType(buf[0])
	body := buf[1:]

	if msgType == MsgHandshakeInit || msgType == MsgHandshakeResp {
		return msgType, body, nil
	}
	if session == nil {
		return 0, nil, errors.New("nil session for encrypted tcp message")
	}
	plain, _, err := session.DecryptNextTCP(body, []byte{byte(msgType)})
	if err != nil {
		return 0, nil, err
	}
	return msgType, plain, nil
}

