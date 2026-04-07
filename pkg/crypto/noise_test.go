package crypto

import (
	"testing"
)

func TestHandshakeRoundTrip(t *testing.T) {
	// Generate two key pairs
	privA, pubA := GenerateKeyPair()
	privB, pubB := GenerateKeyPair()

	// A initiates handshake to B
	initMsg, state, err := HandshakeInitiate(privA, pubB, 42)
	if err != nil {
		t.Fatalf("HandshakeInitiate failed: %v", err)
	}

	t.Logf("initMsg length: %d (expected %d)", len(initMsg), HandshakeInitSize)
	if len(initMsg) != HandshakeInitSize {
		t.Fatalf("initMsg length mismatch: got %d, want %d", len(initMsg), HandshakeInitSize)
	}

	// B responds
	allowedKeys := [][32]byte{pubA}
	respMsg, sessionB, err := HandshakeRespond(privB, initMsg, allowedKeys, 99)
	if err != nil {
		t.Fatalf("HandshakeRespond failed: %v", err)
	}

	t.Logf("respMsg length: %d (expected %d)", len(respMsg), HandshakeRespSize)

	// A finalizes
	sessionA, err := HandshakeFinalize(state, respMsg)
	if err != nil {
		t.Fatalf("HandshakeFinalize failed: %v", err)
	}

	// Verify sessions match
	if sessionA.PeerID != pubB {
		t.Fatal("sessionA.PeerID != pubB")
	}
	if sessionB.PeerID != pubA {
		t.Fatal("sessionB.PeerID != pubA")
	}

	// Test encrypt/decrypt
	plaintext := []byte("hello world")

	// A -> B
	ciphertext, counter, err := sessionA.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := sessionB.Decrypt(ciphertext, counter)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}

	// B -> A
	ciphertext2, counter2, err := sessionB.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt B->A failed: %v", err)
	}

	decrypted2, err := sessionA.Decrypt(ciphertext2, counter2)
	if err != nil {
		t.Fatalf("Decrypt B->A failed: %v", err)
	}

	if string(decrypted2) != string(plaintext) {
		t.Fatalf("decrypted2 mismatch: got %q, want %q", decrypted2, plaintext)
	}

	t.Log("Handshake + encrypt/decrypt roundtrip: OK")
}
