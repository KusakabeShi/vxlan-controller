package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"vxlan-controller/pkg/types"
)

const rejectAfterMessages = 1 << 60

type Session struct {
	LocalIndex  uint32
	RemoteIndex uint32

	// Transport keys are split to avoid nonce/counter collisions between TCP and UDP
	// while still being derived from the same WireGuard-style handshake.
	SendKeyTCP [32]byte
	RecvKeyTCP [32]byte
	SendKeyUDP [32]byte
	RecvKeyUDP [32]byte

	SendCounterTCP atomic.Uint64
	RecvCounterTCP uint64

	SendCounterUDP atomic.Uint64
	RecvWindowUDP  *SlidingWindow

	PeerID types.ClientID

	CreatedAt time.Time
}

func (s *Session) sendAEADTCP() (cipher.AEAD, error) { return chacha20poly1305.New(s.SendKeyTCP[:]) }
func (s *Session) recvAEADTCP() (cipher.AEAD, error) { return chacha20poly1305.New(s.RecvKeyTCP[:]) }
func (s *Session) sendAEADUDP() (cipher.AEAD, error) { return chacha20poly1305.New(s.SendKeyUDP[:]) }
func (s *Session) recvAEADUDP() (cipher.AEAD, error) { return chacha20poly1305.New(s.RecvKeyUDP[:]) }

func (s *Session) EncryptNextTCP(plaintext, aad []byte) ([]byte, uint64, error) {
	counter := s.SendCounterTCP.Add(1) - 1
	if counter >= rejectAfterMessages {
		return nil, 0, errors.New("reject after messages; rehandshake required")
	}
	aead, err := s.sendAEADTCP()
	if err != nil {
		return nil, 0, err
	}
	nonce := nonce12(counter)
	out := aead.Seal(nil, nonce[:], plaintext, aad)
	return out, counter, nil
}

func (s *Session) DecryptNextTCP(ciphertext, aad []byte) ([]byte, uint64, error) {
	counter := s.RecvCounterTCP
	if counter >= rejectAfterMessages {
		return nil, 0, errors.New("reject after messages; rehandshake required")
	}
	aead, err := s.recvAEADTCP()
	if err != nil {
		return nil, 0, err
	}
	nonce := nonce12(counter)
	plain, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, 0, err
	}
	s.RecvCounterTCP++
	return plain, counter, nil
}

func (s *Session) EncryptUDP(counter uint64, plaintext, aad []byte) ([]byte, error) {
	if counter >= rejectAfterMessages {
		return nil, errors.New("reject after messages; rehandshake required")
	}
	aead, err := s.sendAEADUDP()
	if err != nil {
		return nil, err
	}
	nonce := nonce12(counter)
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

func (s *Session) DecryptUDP(counter uint64, ciphertext, aad []byte) ([]byte, error) {
	if counter >= rejectAfterMessages {
		return nil, errors.New("reject after messages; rehandshake required")
	}
	if s.RecvWindowUDP == nil {
		s.RecvWindowUDP = NewSlidingWindow()
	}
	if !s.RecvWindowUDP.Accept(counter) {
		return nil, errors.New("replay / too old counter")
	}
	aead, err := s.recvAEADUDP()
	if err != nil {
		return nil, err
	}
	nonce := nonce12(counter)
	return aead.Open(nil, nonce[:], ciphertext, aad)
}

func (s *Session) NextUDPCounter() (uint64, error) {
	counter := s.SendCounterUDP.Add(1) - 1
	if counter >= rejectAfterMessages {
		return 0, errors.New("reject after messages; rehandshake required")
	}
	return counter, nil
}

func EncodeCounterLE(counter uint64) [8]byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], counter)
	return b
}
