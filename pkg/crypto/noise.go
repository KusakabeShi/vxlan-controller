package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Noise IK pattern handshake implementation (WireGuard-style).
//
// IK pattern:
//   <- s
//   ...
//   -> e, es, s, ss
//   <- e, ee, se

var (
	// Protocol identifier for chaining key initialization
	noiseProtocolName = []byte("Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s")
	noiseConstruction = blake2sHash([]byte("Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s"))

	ErrInvalidHandshake = errors.New("invalid handshake message")
	ErrUnknownPeer      = errors.New("unknown peer public key")
	ErrTimestampReplay  = errors.New("timestamp replay detected")
)

// HandshakeState holds intermediate state during handshake.
type HandshakeState struct {
	LocalStaticPriv  [32]byte
	LocalStaticPub   [32]byte
	RemoteStaticPub  [32]byte
	EphemeralPriv    [32]byte
	EphemeralPub     [32]byte
	ChainingKey      [32]byte
	Hash             [32]byte
	LocalIndex       uint32
}

// TAI64N timestamp (12 bytes).
type TAI64N [12]byte

func nowTAI64N() TAI64N {
	now := time.Now()
	var t TAI64N
	secs := uint64(now.Unix()) + 4611686018427387914 // TAI offset
	binary.BigEndian.PutUint64(t[0:8], secs)
	binary.BigEndian.PutUint32(t[8:12], uint32(now.Nanosecond()))
	return t
}

// PublicKey derives X25519 public key from private key.
func PublicKey(privateKey [32]byte) [32]byte {
	pub, _ := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	var pubKey [32]byte
	copy(pubKey[:], pub)
	return pubKey
}

// GenerateKeyPair generates a new X25519 key pair.
func GenerateKeyPair() (privateKey, publicKey [32]byte) {
	rand.Read(privateKey[:])
	publicKey = PublicKey(privateKey)
	return
}

func blake2sHash(data []byte) [32]byte {
	return blake2s.Sum256(data)
}

func newBlake2sHash() func() hash.Hash {
	return func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}
}

func hmacBlake2s(key, data []byte) [32]byte {
	mac := hmac.New(newBlake2sHash(), key)
	mac.Write(data)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func kdf1(key, input []byte) [32]byte {
	prk := hmacBlake2s(key, input)
	mac := hmac.New(newBlake2sHash(), prk[:])
	mac.Write([]byte{1})
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func kdf2(key, input []byte) ([32]byte, [32]byte) {
	prk := hmacBlake2s(key, input)

	mac1 := hmac.New(newBlake2sHash(), prk[:])
	mac1.Write([]byte{1})
	t1 := mac1.Sum(nil)
	var out1 [32]byte
	copy(out1[:], t1)

	mac2 := hmac.New(newBlake2sHash(), prk[:])
	mac2.Write(t1)
	mac2.Write([]byte{2})
	var out2 [32]byte
	copy(out2[:], mac2.Sum(nil))

	return out1, out2
}

func mixHash(hash *[32]byte, data []byte) {
	h := blake2s.Sum256(append(hash[:], data...))
	*hash = h
}

func mixKey(ck *[32]byte, hash *[32]byte, input []byte) [32]byte {
	c, k := kdf2(ck[:], input)
	*ck = c
	mixHash(hash, []byte{})
	return k
}

func dh(priv, pub [32]byte) [32]byte {
	shared, _ := curve25519.X25519(priv[:], pub[:])
	var result [32]byte
	copy(result[:], shared)
	return result
}

func encryptAEAD(key [32]byte, counter uint64, plaintext, ad []byte) []byte {
	aead, _ := chacha20poly1305.New(key[:])
	nonce := MakeNonce(counter)
	return aead.Seal(nil, nonce[:], plaintext, ad)
}

func decryptAEAD(key [32]byte, counter uint64, ciphertext, ad []byte) ([]byte, error) {
	aead, _ := chacha20poly1305.New(key[:])
	nonce := MakeNonce(counter)
	return aead.Open(nil, nonce[:], ciphertext, ad)
}

// HandshakeInit message sizes
const (
	HandshakeInitSize = 1 + 4 + 32 + 48 + 28 + 16 // msg_type + sender_index + ephemeral + encrypted_static + encrypted_timestamp + mac
	HandshakeRespSize = 1 + 4 + 4 + 32 + 16 + 16   // msg_type + sender_index + receiver_index + ephemeral + encrypted_nothing + mac
)

// HandshakeInitiate creates a HandshakeInit message (initiator side).
func HandshakeInitiate(
	localStaticPriv [32]byte,
	remoteStaticPub [32]byte,
	localIndex uint32,
) (initMsg []byte, state *HandshakeState, err error) {
	localStaticPub := PublicKey(localStaticPriv)

	state = &HandshakeState{
		LocalStaticPriv: localStaticPriv,
		LocalStaticPub:  localStaticPub,
		RemoteStaticPub: remoteStaticPub,
		LocalIndex:      localIndex,
	}

	// Initialize chaining key and hash
	state.ChainingKey = noiseConstruction
	state.Hash = blake2sHash(append(noiseConstruction[:], noiseProtocolName...))

	// Mix responder's static public key into hash (IK pattern: <- s)
	mixHash(&state.Hash, remoteStaticPub[:])

	// Generate ephemeral keypair
	rand.Read(state.EphemeralPriv[:])
	state.EphemeralPub = PublicKey(state.EphemeralPriv)

	// Build message
	initMsg = make([]byte, HandshakeInitSize)
	initMsg[0] = 0x01 // MsgHandshakeInit

	binary.LittleEndian.PutUint32(initMsg[1:5], localIndex)

	// e
	copy(initMsg[5:37], state.EphemeralPub[:])
	mixHash(&state.Hash, state.EphemeralPub[:])

	// es: DH(e_priv, s_pub)
	es := dh(state.EphemeralPriv, remoteStaticPub)
	key := mixKey(&state.ChainingKey, &state.Hash, es[:])

	// Encrypt static public key
	encrypted := encryptAEAD(key, 0, localStaticPub[:], state.Hash[:])
	copy(initMsg[37:85], encrypted)
	mixHash(&state.Hash, encrypted)

	// ss: DH(s_priv, s_pub)
	ss := dh(localStaticPriv, remoteStaticPub)
	key = mixKey(&state.ChainingKey, &state.Hash, ss[:])

	// Encrypt timestamp
	timestamp := nowTAI64N()
	encryptedTs := encryptAEAD(key, 0, timestamp[:], state.Hash[:])
	copy(initMsg[85:113], encryptedTs)
	mixHash(&state.Hash, encryptedTs)

	// MAC
	macKey := kdf1(state.ChainingKey[:], []byte{})
	mac := blake2s.Sum256(append(macKey[:], initMsg[:113]...))
	copy(initMsg[113:129], mac[:16])

	return initMsg, state, nil
}

// HandshakeRespond processes HandshakeInit and creates HandshakeResp (responder side).
func HandshakeRespond(
	localStaticPriv [32]byte,
	initMsg []byte,
	allowedKeys [][32]byte,
	localIndex uint32,
) (respMsg []byte, session *Session, err error) {
	if len(initMsg) != HandshakeInitSize {
		return nil, nil, ErrInvalidHandshake
	}
	if initMsg[0] != 0x01 {
		return nil, nil, ErrInvalidHandshake
	}

	localStaticPub := PublicKey(localStaticPriv)

	// Initialize chaining key and hash
	ck := noiseConstruction
	hash := blake2sHash(append(noiseConstruction[:], noiseProtocolName...))

	// Mix responder's static public key (our key)
	mixHash(&hash, localStaticPub[:])

	senderIndex := binary.LittleEndian.Uint32(initMsg[1:5])

	// Extract ephemeral public key
	var peerEphemeral [32]byte
	copy(peerEphemeral[:], initMsg[5:37])
	mixHash(&hash, peerEphemeral[:])

	// es: DH(s_priv, e_pub)
	es := dh(localStaticPriv, peerEphemeral)
	key := mixKey(&ck, &hash, es[:])

	// Decrypt static public key
	decrypted, err := decryptAEAD(key, 0, initMsg[37:85], hash[:])
	if err != nil {
		return nil, nil, ErrInvalidHandshake
	}
	mixHash(&hash, initMsg[37:85])

	var peerStaticPub [32]byte
	copy(peerStaticPub[:], decrypted)

	// Check if peer is allowed
	allowed := false
	for _, k := range allowedKeys {
		if k == peerStaticPub {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, nil, ErrUnknownPeer
	}

	// ss: DH(s_priv, s_pub)
	ss := dh(localStaticPriv, peerStaticPub)
	key = mixKey(&ck, &hash, ss[:])

	// Decrypt timestamp
	_, err = decryptAEAD(key, 0, initMsg[85:113], hash[:])
	if err != nil {
		return nil, nil, ErrInvalidHandshake
	}
	mixHash(&hash, initMsg[85:113])

	// Verify MAC
	macKey := kdf1(ck[:], []byte{})
	expectedMAC := blake2s.Sum256(append(macKey[:], initMsg[:113]...))
	for i := 0; i < 16; i++ {
		if initMsg[113+i] != expectedMAC[i] {
			return nil, nil, ErrInvalidHandshake
		}
	}

	// Generate responder ephemeral
	var respEphPriv [32]byte
	rand.Read(respEphPriv[:])
	respEphPub := PublicKey(respEphPriv)

	// Build response
	respMsg = make([]byte, HandshakeRespSize)
	respMsg[0] = 0x02 // MsgHandshakeResp

	binary.LittleEndian.PutUint32(respMsg[1:5], localIndex)
	binary.LittleEndian.PutUint32(respMsg[5:9], senderIndex)

	copy(respMsg[9:41], respEphPub[:])
	mixHash(&hash, respEphPub[:])

	// ee: DH(e_priv, e_pub)
	ee := dh(respEphPriv, peerEphemeral)
	key = mixKey(&ck, &hash, ee[:])

	// se: DH(e_priv, s_pub)
	se := dh(respEphPriv, peerStaticPub)
	key = mixKey(&ck, &hash, se[:])

	// Encrypt nothing (confirmation)
	encryptedNothing := encryptAEAD(key, 0, nil, hash[:])
	copy(respMsg[41:57], encryptedNothing)
	mixHash(&hash, encryptedNothing)

	// MAC
	respMACKey := kdf1(ck[:], []byte{})
	respMAC := blake2s.Sum256(append(respMACKey[:], respMsg[:57]...))
	copy(respMsg[57:73], respMAC[:16])

	// Derive session keys
	sendKey, recvKey := kdf2(ck[:], nil)

	session = &Session{
		LocalIndex:  localIndex,
		RemoteIndex: senderIndex,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		PeerID:      peerStaticPub,
	}

	return respMsg, session, nil
}

// HandshakeFinalize processes HandshakeResp and derives session keys (initiator side).
func HandshakeFinalize(
	state *HandshakeState,
	respMsg []byte,
) (session *Session, err error) {
	if len(respMsg) != HandshakeRespSize {
		return nil, ErrInvalidHandshake
	}
	if respMsg[0] != 0x02 {
		return nil, ErrInvalidHandshake
	}

	remoteIndex := binary.LittleEndian.Uint32(respMsg[1:5])
	receiverIndex := binary.LittleEndian.Uint32(respMsg[5:9])

	if receiverIndex != state.LocalIndex {
		return nil, ErrInvalidHandshake
	}

	var respEphPub [32]byte
	copy(respEphPub[:], respMsg[9:41])
	mixHash(&state.Hash, respEphPub[:])

	// ee: DH(e_priv, e_pub)
	ee := dh(state.EphemeralPriv, respEphPub)
	key := mixKey(&state.ChainingKey, &state.Hash, ee[:])

	// se: DH(s_priv, e_pub)
	se := dh(state.LocalStaticPriv, respEphPub)
	key = mixKey(&state.ChainingKey, &state.Hash, se[:])

	// Decrypt nothing (verification)
	_, err = decryptAEAD(key, 0, respMsg[41:57], state.Hash[:])
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	mixHash(&state.Hash, respMsg[41:57])

	// Verify MAC
	macKey := kdf1(state.ChainingKey[:], []byte{})
	expectedMAC := blake2s.Sum256(append(macKey[:], respMsg[:57]...))
	for i := 0; i < 16; i++ {
		if respMsg[57+i] != expectedMAC[i] {
			return nil, ErrInvalidHandshake
		}
	}

	// Derive session keys (initiator: recv/send are swapped vs responder)
	recvKey, sendKey := kdf2(state.ChainingKey[:], nil)

	session = &Session{
		LocalIndex:  state.LocalIndex,
		RemoteIndex: remoteIndex,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		PeerID:      state.RemoteStaticPub,
	}

	return session, nil
}
