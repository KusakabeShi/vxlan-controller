package crypto

import (
	"testing"
	"time"

	"vxlan-controller/pkg/types"
)

func TestNoiseHandshakeRoundTrip(t *testing.T) {
	var initiatorPriv [32]byte
	var responderPriv [32]byte
	for i := 0; i < 32; i++ {
		initiatorPriv[i] = byte(0x11 + i)
		responderPriv[i] = byte(0x77 + i)
	}
	responderPub, err := PublicKey(responderPriv)
	if err != nil {
		t.Fatal(err)
	}
	initiatorPub, err := PublicKey(initiatorPriv)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1700000000, 123456789)
	initMsg, st, err := HandshakeInitiate(initiatorPriv, responderPub, now)
	if err != nil {
		t.Fatal(err)
	}

	allowed := func(peer [32]byte) bool { return types.ClientID(peer).Equal(types.ClientID(initiatorPub)) }
	checkTS := func(peer types.ClientID, ts [12]byte) bool { return true }
	respMsg, respSess, info, err := HandshakeRespond(responderPriv, initMsg, allowed, checkTS, now)
	if err != nil {
		t.Fatal(err)
	}
	if !info.PeerID.Equal(types.ClientID(initiatorPub)) {
		t.Fatalf("peer id mismatch")
	}

	initSess, err := HandshakeFinalize(st, respMsg)
	if err != nil {
		t.Fatal(err)
	}

	if initSess.SendKeyTCP != respSess.RecvKeyTCP {
		t.Fatalf("initiator tcp send != responder tcp recv")
	}
	if initSess.RecvKeyTCP != respSess.SendKeyTCP {
		t.Fatalf("initiator tcp recv != responder tcp send")
	}
	if initSess.SendKeyUDP != respSess.RecvKeyUDP {
		t.Fatalf("initiator udp send != responder udp recv")
	}
	if initSess.RecvKeyUDP != respSess.SendKeyUDP {
		t.Fatalf("initiator udp recv != responder udp send")
	}
	if initSess.RemoteIndex != respSess.LocalIndex || initSess.LocalIndex != respSess.RemoteIndex {
		t.Fatalf("index mismatch")
	}
}
