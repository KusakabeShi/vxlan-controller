package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"vxlan-controller/pkg/types"
)

var (
	construction = []byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
	identifier   = []byte("WireGuard v1 zx2c4 Jason@zx2c4.com")
	labelMac1    = []byte("mac1----")
)

const (
	// WireGuard handshake packet sizes (see wireguard.com/protocol):
	// initiation: 148 bytes, response: 92 bytes.
	HandshakeInitLen = 148
	HandshakeRespLen = 92
)

type InitiatorState struct {
	SenderIndex uint32

	localStaticPriv  [32]byte
	localStaticPub   [32]byte
	remoteStaticPub  [32]byte
	ephemeralPriv    [32]byte
	chainingKey      [32]byte
	hash             [32]byte
}

func PublicKey(priv [32]byte) ([32]byte, error) {
	var pub [32]byte
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, err
	}
	copy(pub[:], p)
	return pub, nil
}

func HandshakeInitiate(localStaticPriv, remoteStaticPub [32]byte, now time.Time) ([]byte, *InitiatorState, error) {
	localStaticPub, err := PublicKey(localStaticPriv)
	if err != nil {
		return nil, nil, err
	}

	var st InitiatorState
	st.localStaticPriv = localStaticPriv
	st.localStaticPub = localStaticPub
	st.remoteStaticPub = remoteStaticPub
	st.SenderIndex = randUint32()

	st.chainingKey = hash32(construction)
	tmp := hash32(append(st.chainingKey[:], identifier...))
	st.hash = hash32(append(tmp[:], remoteStaticPub[:]...))

	st.ephemeralPriv = dhGenerate()
	epub, err := curve25519.X25519(st.ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	var ephemeralPub [32]byte
	copy(ephemeralPub[:], epub)

	st.hash = hash32(append(st.hash[:], ephemeralPub[:]...))

	temp := hmac32(st.chainingKey[:], ephemeralPub[:])
	st.chainingKey = hmac32(temp[:], []byte{0x1})

	dh1, err := dh(st.ephemeralPriv, remoteStaticPub)
	if err != nil {
		return nil, nil, err
	}
	temp = hmac32(st.chainingKey[:], dh1[:])
	st.chainingKey = hmac32(temp[:], []byte{0x1})
	key := hmac32(temp[:], append(st.chainingKey[:], 0x2))

	encryptedStatic, err := aeadSeal(key[:], 0, st.localStaticPub[:], st.hash[:])
	if err != nil {
		return nil, nil, err
	}
	st.hash = hash32(append(st.hash[:], encryptedStatic...))

	dh2, err := dh(localStaticPriv, remoteStaticPub)
	if err != nil {
		return nil, nil, err
	}
	temp = hmac32(st.chainingKey[:], dh2[:])
	st.chainingKey = hmac32(temp[:], []byte{0x1})
	key = hmac32(temp[:], append(st.chainingKey[:], 0x2))

	ts := tai64n(now)
	encryptedTimestamp, err := aeadSeal(key[:], 0, ts[:], st.hash[:])
	if err != nil {
		return nil, nil, err
	}
	st.hash = hash32(append(st.hash[:], encryptedTimestamp...))

	out := make([]byte, HandshakeInitLen)
	out[0] = 1
	out[1], out[2], out[3] = 0, 0, 0
	binary.LittleEndian.PutUint32(out[4:8], st.SenderIndex)
	copy(out[8:40], ephemeralPub[:])
	copy(out[40:88], encryptedStatic)
	copy(out[88:116], encryptedTimestamp)

	macKey := hash32(append(labelMac1, remoteStaticPub[:]...))
	mac1 := mac16(macKey[:], out[:116])
	copy(out[116:132], mac1[:])
	// mac2 is zeros (no cookie).
	for i := 132; i < 148; i++ {
		out[i] = 0
	}
	return out, &st, nil
}

func HandshakeFinalize(st *InitiatorState, resp []byte) (*Session, error) {
	if st == nil {
		return nil, errors.New("nil handshake state")
	}
	if len(resp) != HandshakeRespLen {
		return nil, fmt.Errorf("invalid handshake response length: %d", len(resp))
	}

	if resp[0] != 2 || resp[1] != 0 || resp[2] != 0 || resp[3] != 0 {
		return nil, errors.New("handshake response header invalid")
	}
	macKey := hash32(append(labelMac1, st.localStaticPub[:]...))
	wantMac := mac16(macKey[:], resp[:60])
	if !bytes.Equal(wantMac[:], resp[60:76]) {
		return nil, errors.New("handshake response mac mismatch")
	}

	responderIndex := binary.LittleEndian.Uint32(resp[4:8])
	receiverIndex := binary.LittleEndian.Uint32(resp[8:12])
	if receiverIndex != st.SenderIndex {
		return nil, errors.New("handshake response receiver_index mismatch")
	}

	var responderEphPub [32]byte
	copy(responderEphPub[:], resp[12:44])
	encryptedNothing := resp[44 : 44+16]

	hashv := st.hash
	ck := st.chainingKey

	hashv = hash32(append(hashv[:], responderEphPub[:]...))

	temp := hmac32(ck[:], responderEphPub[:])
	ck = hmac32(temp[:], []byte{0x1})

	dh1, err := dh(st.ephemeralPriv, responderEphPub)
	if err != nil {
		return nil, err
	}
	temp = hmac32(ck[:], dh1[:])
	ck = hmac32(temp[:], []byte{0x1})

	dh2, err := dh(st.localStaticPriv, responderEphPub)
	if err != nil {
		return nil, err
	}
	temp = hmac32(ck[:], dh2[:])
	ck = hmac32(temp[:], []byte{0x1})

	var psk [32]byte
	temp = hmac32(ck[:], psk[:])
	ck = hmac32(temp[:], []byte{0x1})
	temp2 := hmac32(temp[:], append(ck[:], 0x2))
	key := hmac32(temp[:], append(temp2[:], 0x3))
	hashv = hash32(append(hashv[:], temp2[:]...))

	if _, err := aeadOpen(key[:], 0, encryptedNothing, hashv[:]); err != nil {
		return nil, fmt.Errorf("decrypt empty: %w", err)
	}
	hashv = hash32(append(hashv[:], encryptedNothing...))

	sendKey, recvKey := deriveDataKeys(ck, true)

	sess := &Session{
		LocalIndex:  st.SenderIndex,
		RemoteIndex: responderIndex,
		SendKeyTCP:  deriveTransportKey(sendKey, "tcp"),
		RecvKeyTCP:  deriveTransportKey(recvKey, "tcp"),
		SendKeyUDP:  deriveTransportKey(sendKey, "udp"),
		RecvKeyUDP:  deriveTransportKey(recvKey, "udp"),
		PeerID:      types.ClientID(st.remoteStaticPub),
		CreatedAt:   time.Now(),
		RecvWindowUDP:  NewSlidingWindow(),
	}
	return sess, nil
}

type ResponderResult struct {
	PeerStaticPub [32]byte
	PeerID        types.ClientID
	TimestampTAI  [12]byte
}

func HandshakeRespond(
	localStaticPriv [32]byte,
	initMsg []byte,
	allowed func(peerStaticPub [32]byte) bool,
	checkAndUpdateTimestamp func(peer types.ClientID, ts [12]byte) bool,
	now time.Time,
) (respMsg []byte, session *Session, info ResponderResult, err error) {
	if len(initMsg) != HandshakeInitLen {
		return nil, nil, info, fmt.Errorf("invalid handshake init length: %d", len(initMsg))
	}

	localStaticPub, err := PublicKey(localStaticPriv)
	if err != nil {
		return nil, nil, info, err
	}

	if initMsg[0] != 1 || initMsg[1] != 0 || initMsg[2] != 0 || initMsg[3] != 0 {
		return nil, nil, info, errors.New("handshake init header invalid")
	}
	macKey := hash32(append(labelMac1, localStaticPub[:]...))
	wantMac := mac16(macKey[:], initMsg[:116])
	if !bytes.Equal(wantMac[:], initMsg[116:132]) {
		return nil, nil, info, errors.New("handshake init mac mismatch")
	}

	var initiatorIndex uint32 = binary.LittleEndian.Uint32(initMsg[4:8])
	var initiatorEphPub [32]byte
	copy(initiatorEphPub[:], initMsg[8:40])
	encryptedStatic := initMsg[40 : 40+48]
	encryptedTimestamp := initMsg[88 : 88+28]

	ck := hash32(construction)
	tmp := hash32(append(ck[:], identifier...))
	hashv := hash32(append(tmp[:], localStaticPub[:]...))

	hashv = hash32(append(hashv[:], initiatorEphPub[:]...))

	temp := hmac32(ck[:], initiatorEphPub[:])
	ck = hmac32(temp[:], []byte{0x1})

	dh1, err := dh(localStaticPriv, initiatorEphPub)
	if err != nil {
		return nil, nil, info, err
	}
	temp = hmac32(ck[:], dh1[:])
	ck = hmac32(temp[:], []byte{0x1})
	key := hmac32(temp[:], append(ck[:], 0x2))

	plainStatic, err := aeadOpen(key[:], 0, encryptedStatic, hashv[:])
	if err != nil {
		return nil, nil, info, fmt.Errorf("decrypt static: %w", err)
	}
	if len(plainStatic) != 32 {
		return nil, nil, info, fmt.Errorf("decrypt static: invalid len %d", len(plainStatic))
	}
	var initiatorStaticPub [32]byte
	copy(initiatorStaticPub[:], plainStatic)
	info.PeerStaticPub = initiatorStaticPub
	info.PeerID = types.ClientID(initiatorStaticPub)

	if allowed != nil && !allowed(initiatorStaticPub) {
		return nil, nil, info, errors.New("peer not allowed")
	}

	hashv = hash32(append(hashv[:], encryptedStatic...))

	dh2, err := dh(localStaticPriv, initiatorStaticPub)
	if err != nil {
		return nil, nil, info, err
	}
	temp = hmac32(ck[:], dh2[:])
	ck = hmac32(temp[:], []byte{0x1})
	key = hmac32(temp[:], append(ck[:], 0x2))

	plainTS, err := aeadOpen(key[:], 0, encryptedTimestamp, hashv[:])
	if err != nil {
		return nil, nil, info, fmt.Errorf("decrypt timestamp: %w", err)
	}
	if len(plainTS) != 12 {
		return nil, nil, info, fmt.Errorf("timestamp invalid len %d", len(plainTS))
	}
	copy(info.TimestampTAI[:], plainTS)
	if checkAndUpdateTimestamp != nil && !checkAndUpdateTimestamp(info.PeerID, info.TimestampTAI) {
		return nil, nil, info, errors.New("replayed/old timestamp")
	}

	hashv = hash32(append(hashv[:], encryptedTimestamp...))

	responderIndex := randUint32()
	responderEphPriv := dhGenerate()
	responderEphPubBytes, err := curve25519.X25519(responderEphPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, info, err
	}
	var responderEphPub [32]byte
	copy(responderEphPub[:], responderEphPubBytes)

	hashv = hash32(append(hashv[:], responderEphPub[:]...))

	temp = hmac32(ck[:], responderEphPub[:])
	ck = hmac32(temp[:], []byte{0x1})

	dh3, err := dh(responderEphPriv, initiatorEphPub)
	if err != nil {
		return nil, nil, info, err
	}
	temp = hmac32(ck[:], dh3[:])
	ck = hmac32(temp[:], []byte{0x1})

	dh4, err := dh(responderEphPriv, initiatorStaticPub)
	if err != nil {
		return nil, nil, info, err
	}
	temp = hmac32(ck[:], dh4[:])
	ck = hmac32(temp[:], []byte{0x1})

	var psk [32]byte
	temp = hmac32(ck[:], psk[:])
	ck = hmac32(temp[:], []byte{0x1})
	temp2 := hmac32(temp[:], append(ck[:], 0x2))
	key = hmac32(temp[:], append(temp2[:], 0x3))
	hashv = hash32(append(hashv[:], temp2[:]...))

	encryptedNothing, err := aeadSeal(key[:], 0, nil, hashv[:])
	if err != nil {
		return nil, nil, info, err
	}
	if len(encryptedNothing) != 16 {
		return nil, nil, info, fmt.Errorf("encrypted_nothing length %d", len(encryptedNothing))
	}
	hashv = hash32(append(hashv[:], encryptedNothing...))

	out := make([]byte, HandshakeRespLen)
	out[0] = 2
	out[1], out[2], out[3] = 0, 0, 0
	binary.LittleEndian.PutUint32(out[4:8], responderIndex)
	binary.LittleEndian.PutUint32(out[8:12], initiatorIndex)
	copy(out[12:44], responderEphPub[:])
	copy(out[44:60], encryptedNothing)

	respMacKey := hash32(append(labelMac1, initiatorStaticPub[:]...))
	mac1 := mac16(respMacKey[:], out[:60])
	copy(out[60:76], mac1[:])
	for i := 76; i < 92; i++ {
		out[i] = 0
	}

	sendKey, recvKey := deriveDataKeys(ck, false)
	sess := &Session{
		LocalIndex:  responderIndex,
		RemoteIndex: initiatorIndex,
		SendKeyTCP:  deriveTransportKey(sendKey, "tcp"),
		RecvKeyTCP:  deriveTransportKey(recvKey, "tcp"),
		SendKeyUDP:  deriveTransportKey(sendKey, "udp"),
		RecvKeyUDP:  deriveTransportKey(recvKey, "udp"),
		PeerID:      types.ClientID(initiatorStaticPub),
		CreatedAt:   now,
		RecvWindowUDP:  NewSlidingWindow(),
	}
	return out, sess, info, nil
}

func deriveTransportKey(master [32]byte, label string) (out [32]byte) {
	// Domain-separate TCP vs UDP so counters can be maintained independently per transport
	// without risking nonce reuse under the same key.
	k := hmac32(master[:], []byte("vxlan-controller:"+label))
	copy(out[:], k[:])
	return out
}

func deriveDataKeys(chainingKey [32]byte, initiator bool) (send [32]byte, recv [32]byte) {
	temp1 := hmac32(chainingKey[:], nil)
	temp2 := hmac32(temp1[:], []byte{0x1})
	temp3 := hmac32(temp1[:], append(temp2[:], 0x2))
	if initiator {
		copy(send[:], temp2[:])
		copy(recv[:], temp3[:])
	} else {
		// responder: receiving_key = temp2, sending_key = temp3
		copy(recv[:], temp2[:])
		copy(send[:], temp3[:])
	}
	return send, recv
}

func aeadSeal(key []byte, counter uint64, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := nonce12(counter)
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

func aeadOpen(key []byte, counter uint64, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := nonce12(counter)
	return aead.Open(nil, nonce[:], ciphertext, aad)
}

func dhGenerate() [32]byte {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		panic(err)
	}
	// curve25519.X25519 will clamp.
	return priv
}

func dh(priv [32]byte, pub [32]byte) ([32]byte, error) {
	var out [32]byte
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return out, err
	}
	copy(out[:], shared)
	return out, nil
}

func hash32(input []byte) [32]byte { return blake2s.Sum256(input) }

func hmac32(key, input []byte) [32]byte {
	h := hmac.New(func() hash.Hash {
		hh, err := blake2s.New256(nil)
		if err != nil {
			panic(err)
		}
		return hh
	}, key)
	_, _ = h.Write(input)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func mac16(key, input []byte) [16]byte {
	h, err := blake2s.New128(key)
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(input)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func randUint32() uint32 {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(err)
	}
	v := binary.LittleEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

func tai64n(t time.Time) [12]byte {
	// https://cr.yp.to/libtai/tai64.html
	// tai64 = 0x400000000000000a + unix seconds
	secs := uint64(t.Unix()) + 0x400000000000000a
	nsec := uint32(t.Nanosecond())
	var out [12]byte
	binary.BigEndian.PutUint64(out[0:8], secs)
	binary.BigEndian.PutUint32(out[8:12], nsec)
	return out
}
