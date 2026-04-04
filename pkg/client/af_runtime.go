package client

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/types"
)

type AFRuntime struct {
	AF        types.AFName
	BindAddr  netip.Addr
	CommPort  uint16
	ProbePort uint16

	CommUDP  net.PacketConn
	ProbeUDP net.PacketConn

	mu sync.Mutex
	commSessionsByIndex  map[uint32]*crypto.Session
	probeSessionsByIndex map[uint32]*crypto.Session
	probeSessionsByPeer  map[types.ClientID]*crypto.Session
	probeLastTAI64NByPeer map[types.ClientID][12]byte
	probePendingInitiations map[uint32]*crypto.InitiatorState // sender_index -> state
}

func NewAFRuntime(af types.AFName, bindAddr netip.Addr, commPort, probePort uint16) (*AFRuntime, error) {
	if !bindAddr.IsValid() {
		return nil, errors.New("invalid bind addr")
	}
	commAddr := netip.AddrPortFrom(bindAddr, commPort).String()
	comm, err := listenPacketRetry("udp", commAddr, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("listen comm udp %s: %w", commAddr, err)
	}
	probeAddr := netip.AddrPortFrom(bindAddr, probePort).String()
	probe, err := listenPacketRetry("udp", probeAddr, 3*time.Second)
	if err != nil {
		_ = comm.Close()
		return nil, fmt.Errorf("listen probe udp %s: %w", probeAddr, err)
	}
	return &AFRuntime{
		AF: af,
		BindAddr: bindAddr,
		CommPort: commPort,
		ProbePort: probePort,
		CommUDP: comm,
		ProbeUDP: probe,
		commSessionsByIndex: make(map[uint32]*crypto.Session),
		probeSessionsByIndex: make(map[uint32]*crypto.Session),
		probeSessionsByPeer: make(map[types.ClientID]*crypto.Session),
		probeLastTAI64NByPeer: make(map[types.ClientID][12]byte),
		probePendingInitiations: make(map[uint32]*crypto.InitiatorState),
	}, nil
}

func listenPacketRetry(network, addr string, maxWait time.Duration) (net.PacketConn, error) {
	deadline := time.Now().Add(maxWait)
	backoff := 50 * time.Millisecond
	for {
		pc, err := net.ListenPacket(network, addr)
		if err == nil {
			return pc, nil
		}
		// IPv6 addresses may be "tentative" (DAD) right after assignment; binding can return EADDRNOTAVAIL.
		if errors.Is(err, syscall.EADDRNOTAVAIL) && time.Now().Before(deadline) {
			time.Sleep(backoff)
			if backoff < 300*time.Millisecond {
				backoff *= 2
			}
			continue
		}
		return nil, err
	}
}

func (r *AFRuntime) Close() error {
	var err error
	if r.CommUDP != nil {
		err = r.CommUDP.Close()
	}
	if r.ProbeUDP != nil {
		_ = r.ProbeUDP.Close()
	}
	return err
}

func (r *AFRuntime) RegisterCommSession(sess *crypto.Session) {
	if sess == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commSessionsByIndex[sess.LocalIndex] = sess
}

func (r *AFRuntime) UnregisterCommSession(localIndex uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.commSessionsByIndex, localIndex)
}

func (r *AFRuntime) FindCommSession(localIndex uint32) *crypto.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.commSessionsByIndex[localIndex]
}

func (r *AFRuntime) RegisterProbeSession(sess *crypto.Session) {
	if sess == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probeSessionsByIndex[sess.LocalIndex] = sess
	r.probeSessionsByPeer[sess.PeerID] = sess
}

func (r *AFRuntime) UnregisterProbeSession(localIndex uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess := r.probeSessionsByIndex[localIndex]; sess != nil {
		delete(r.probeSessionsByPeer, sess.PeerID)
	}
	delete(r.probeSessionsByIndex, localIndex)
}

func (r *AFRuntime) FindProbeSession(localIndex uint32) *crypto.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.probeSessionsByIndex[localIndex]
}

func (r *AFRuntime) FindProbeSessionByPeer(peer types.ClientID) *crypto.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.probeSessionsByPeer[peer]
}

func (r *AFRuntime) CheckAndUpdateProbeTAI64N(peer types.ClientID, ts [12]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, ok := r.probeLastTAI64NByPeer[peer]
	if ok && tai64nLessOrEqual(ts, prev) {
		return false
	}
	r.probeLastTAI64NByPeer[peer] = ts
	return true
}

func tai64nLessOrEqual(a, b [12]byte) bool {
	for i := 0; i < 12; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true
}

func (r *AFRuntime) RegisterProbeInitiation(st *crypto.InitiatorState) {
	if st == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probePendingInitiations[st.SenderIndex] = st
}

func (r *AFRuntime) TakeProbeInitiation(receiverIndex uint32) *crypto.InitiatorState {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.probePendingInitiations[receiverIndex]
	delete(r.probePendingInitiations, receiverIndex)
	return st
}
