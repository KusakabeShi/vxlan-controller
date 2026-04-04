package types

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type ClientID [32]byte
type ControllerID [32]byte
type AFName string

func (id ClientID) Bytes() []byte {
	b := make([]byte, 32)
	copy(b, id[:])
	return b
}

func (id ClientID) String() string { return base64.StdEncoding.EncodeToString(id[:]) }

func (id ClientID) Equal(other ClientID) bool { return subtle.ConstantTimeCompare(id[:], other[:]) == 1 }

func CompareClientID(a, b ClientID) int { return bytes.Compare(a[:], b[:]) }

func ParseKey32Base64(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, errors.New("empty base64 key")
	}

	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return out, fmt.Errorf("decode base64: %w", err)
		}
	}
	if len(dec) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(dec))
	}
	copy(out[:], dec)
	return out, nil
}

func MustMAC(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) != 6 {
		panic("invalid mac length")
	}
	out := make(net.HardwareAddr, 6)
	copy(out, mac)
	return out
}

func NetIPToBytes(a netip.Addr) []byte {
	if !a.IsValid() {
		return nil
	}
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func BytesToNetIP(b []byte) (netip.Addr, error) {
	switch len(b) {
	case 0:
		return netip.Addr{}, nil
	case 4:
		var a4 [4]byte
		copy(a4[:], b)
		return netip.AddrFrom4(a4), nil
	case 16:
		var a16 [16]byte
		copy(a16[:], b)
		return netip.AddrFrom16(a16), nil
	default:
		return netip.Addr{}, fmt.Errorf("invalid ip bytes length: %d", len(b))
	}
}

