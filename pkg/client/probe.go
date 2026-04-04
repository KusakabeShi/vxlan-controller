package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
	pb "vxlan-controller/proto"
)

type probeResponse struct {
	from    types.ClientID
	af      types.AFName
	batchID uint64
	probeID uint64
	seq     uint32
	dstTS   int64
}

type probeSample struct{ ms float64 }

func (c *Client) probeUDPReadLoop(ctx context.Context, af types.AFName, rt *AFRuntime) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := rt.ProbeUDP.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		if n < 1 {
			continue
		}
		msgType := protocol.MsgType(buf[0])
		data := make([]byte, n)
		copy(data, buf[:n])

		switch msgType {
		case protocol.MsgHandshakeInit:
			if len(data) != 1+crypto.HandshakeInitLen {
				continue
			}
			initPayload := data[1:]
			allowed := func(peer [32]byte) bool { return c.isKnownClient(types.ClientID(peer)) }
			checkTS := func(peer types.ClientID, ts [12]byte) bool { return rt.CheckAndUpdateProbeTAI64N(peer, ts) }
			respPayload, sess, _, err := crypto.HandshakeRespond(c.privateKey, initPayload, allowed, checkTS, c.Now())
			if err != nil {
				continue
			}
			rt.RegisterProbeSession(sess)
			out := make([]byte, 1+len(respPayload))
			out[0] = byte(protocol.MsgHandshakeResp)
			copy(out[1:], respPayload)
			_, _ = rt.ProbeUDP.WriteTo(out, addr)
		case protocol.MsgHandshakeResp:
			if len(data) != 1+crypto.HandshakeRespLen {
				continue
			}
			respPayload := data[1:]
			// HandshakeResp layout: sender_index(4) at [4:8], receiver_index(4) at [8:12].
			// We must match the receiver_index which equals our initiation SenderIndex.
			myInitiatorIndex := binary.LittleEndian.Uint32(respPayload[8:12])
			st := rt.TakeProbeInitiation(myInitiatorIndex)
			if st == nil {
				continue
			}
			sess, err := crypto.HandshakeFinalize(st, respPayload)
			if err != nil {
				continue
			}
			rt.RegisterProbeSession(sess)
		case protocol.MsgProbeRequest, protocol.MsgProbeResponse:
			msgType, plain, peerID, err := protocol.ReadUDPPacket(data, rt.FindProbeSession)
			if err != nil {
				continue
			}
			if msgType == protocol.MsgProbeRequest {
				var req pb.ProbeRequest
				if err := proto.Unmarshal(plain, &req); err != nil {
					continue
				}
				// reply
				resp := &pb.ProbeResponse{
					BatchId:            req.GetBatchId(),
					Seq:                req.GetSeq(),
					ProbeId:            req.GetProbeId(),
					SourceClientId:     req.GetSourceClientId(),
					DstTimestampUnixNs: c.Now().UnixNano(),
				}
				b, _ := proto.Marshal(resp)
				sess := rt.FindProbeSessionByPeer(peerID)
				if sess == nil {
					continue
				}
				_ = protocol.WriteUDPPacket(rt.ProbeUDP, addr, sess, protocol.MsgProbeResponse, b)
			} else {
				var resp pb.ProbeResponse
				if err := proto.Unmarshal(plain, &resp); err != nil {
					continue
				}
				if len(resp.SourceClientId) != 32 {
					continue
				}
				// source_client_id is requester; only accept if it's us
				var src types.ClientID
				copy(src[:], resp.SourceClientId)
				if !src.Equal(c.clientID) {
					continue
				}
				c.probeMu.Lock()
				ch := c.probeRespCh[resp.BatchId]
				c.probeMu.Unlock()
				if ch != nil {
					select {
					case ch <- probeResponse{from: peerID, af: af, batchID: resp.BatchId, probeID: resp.ProbeId, seq: resp.Seq, dstTS: resp.DstTimestampUnixNs}:
					default:
					}
				}
			}
		default:
		}
	}
}

func (c *Client) isKnownClient(id types.ClientID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Use authority view if available, else any synced view.
	if c.authority != nil {
		ctrl := c.controllers[*c.authority]
		if ctrl != nil {
			ctrl.mu.Lock()
			v := ctrl.View
			ctrl.mu.Unlock()
			if v != nil {
				_, ok := v.ClientsByID[id]
				return ok
			}
		}
	}
	for _, ctrl := range c.controllers {
		ctrl.mu.Lock()
		v := ctrl.View
		ctrl.mu.Unlock()
		if v != nil {
			if _, ok := v.ClientsByID[id]; ok {
				return true
			}
		}
	}
	return false
}

func (c *Client) ensureProbeSession(ctx context.Context, af types.AFName, rt *AFRuntime, peer types.ClientID, peerAddr netip.AddrPort) (*crypto.Session, error) {
	if s := rt.FindProbeSessionByPeer(peer); s != nil {
		return s, nil
	}

	backoff := 200 * time.Millisecond
	deadline := time.Now().Add(5 * time.Second)
	for {
		initPayload, st, err := crypto.HandshakeInitiate(c.privateKey, [32]byte(peer), c.Now())
		if err != nil {
			return nil, err
		}
		rt.RegisterProbeInitiation(st)
		pkt := make([]byte, 1+len(initPayload))
		pkt[0] = byte(protocol.MsgHandshakeInit)
		copy(pkt[1:], initPayload)

		_, _ = rt.ProbeUDP.WriteTo(pkt, net.UDPAddrFromAddrPort(peerAddr))

		// Wait a bit for response to be processed by read loop, then retransmit with backoff.
		waitUntil := time.Now().Add(backoff)
		for time.Now().Before(waitUntil) {
			if s := rt.FindProbeSessionByPeer(peer); s != nil {
				return s, nil
			}
			if time.Now().After(deadline) {
				return nil, errors.New("probe handshake timeout")
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(30 * time.Millisecond):
			}
		}
		if backoff < time.Second {
			backoff *= 2
		}
		if time.Now().After(deadline) {
			return nil, errors.New("probe handshake timeout")
		}
	}
}

func (c *Client) handleProbeRequest(ctrlID types.ControllerID, req *pb.ControllerProbeRequest) {
	// Only handle if from current authority controller.
	c.mu.Lock()
	auth := c.authority
	if auth == nil {
		if c.pendingProbe != nil {
			c.pendingProbe[ctrlID] = req
		}
		c.mu.Unlock()
		c.log.Info("probe request queued (no authority yet)",
			zap.String("controller", types.ClientID(ctrlID).String()),
			zap.Uint64("batch_id", req.GetBatchId()),
		)
		return
	}
	c.mu.Unlock()
	if *auth != ctrlID {
		c.log.Info("probe request ignored (not authority)",
			zap.String("controller", types.ClientID(ctrlID).String()),
			zap.String("authority", types.ClientID(*auth).String()),
			zap.Uint64("batch_id", req.GetBatchId()),
		)
		return
	}
	c.log.Info("probe request accepted",
		zap.String("controller", types.ClientID(ctrlID).String()),
		zap.Uint64("batch_id", req.GetBatchId()),
	)
	c.runProbe(req)
}

func (c *Client) runProbe(req *pb.ControllerProbeRequest) {
	c.log.Info("probe started", zap.Uint64("batch_id", req.GetBatchId()), zap.Uint32("probe_times", req.GetProbeTimes()))
	// Snapshot authority view.
	c.mu.Lock()
	auth := c.authority
	var view *ControllerView
	if auth != nil {
		ctrl := c.controllers[*auth]
		if ctrl != nil {
			ctrl.mu.Lock()
			view = ctrl.View
			ctrl.mu.Unlock()
		}
	}
	c.mu.Unlock()
	if view == nil {
		return
	}

	batchID := req.GetBatchId()
	respCh := make(chan probeResponse, 4096)
	c.probeMu.Lock()
	c.probeRespCh[batchID] = respCh
	c.probeMu.Unlock()
	defer func() {
		c.probeMu.Lock()
		delete(c.probeRespCh, batchID)
		c.probeMu.Unlock()
	}()

	// Prepare peer list.
	peers := make([]types.ClientID, 0, len(view.ClientsByID))
	for id := range view.ClientsByID {
		if id.Equal(c.clientID) {
			continue
		}
		peers = append(peers, id)
	}

	results := make(map[types.ClientID]map[types.AFName][]probeSample)
	sent := make(map[types.ClientID]map[types.AFName]int)
	got := make(map[types.ClientID]map[types.AFName]int)

	for _, peer := range peers {
		results[peer] = make(map[types.AFName][]probeSample)
		sent[peer] = make(map[types.AFName]int)
		got[peer] = make(map[types.AFName]int)
	}

	type meta struct {
		peer  types.ClientID
		af    types.AFName
		seq   uint32
		srcTS int64
	}
	metaByProbeID := make(map[uint64]meta)

	for i := 0; i < int(req.GetProbeTimes()); i++ {
		seq := uint32(i)
		for _, peer := range peers {
			for afName, afCfg := range c.cfg.AFSettings {
				if afCfg == nil || !afCfg.Enable {
					continue
				}
				peerIP, peerProbePort, err := view.EndpointIP(peer, afName)
				if err != nil || !peerIP.IsValid() || peerProbePort == 0 {
					continue
				}
				rt := c.afRuntime[afName]
				if rt == nil {
					continue
				}
				peerAddr := netip.AddrPortFrom(peerIP, peerProbePort)
				sess, err := c.ensureProbeSession(c.ctx, afName, rt, peer, peerAddr)
				if err != nil {
					continue
				}
				probeID := randUint64()
				srcTS := c.Now().UnixNano()
				metaByProbeID[probeID] = meta{peer: peer, af: afName, seq: seq, srcTS: srcTS}
				msg := &pb.ProbeRequest{
					BatchId:            batchID,
					Seq:                seq,
					ProbeId:            probeID,
					SourceClientId:     c.clientID.Bytes(),
					SrcTimestampUnixNs: srcTS,
				}
				b, _ := proto.Marshal(msg)
				_ = protocol.WriteUDPPacket(rt.ProbeUDP, net.UDPAddrFromAddrPort(peerAddr), sess, protocol.MsgProbeRequest, b)
				sent[peer][afName]++
			}
		}
		time.Sleep(time.Duration(req.GetInProbeIntervalMs()) * time.Millisecond)
	}

	timeout := time.After(time.Duration(req.GetProbeTimeoutMs()) * time.Millisecond)
collect:
	for {
		select {
		case <-timeout:
			break collect
		case r := <-respCh:
			m, ok := metaByProbeID[r.probeID]
			if !ok {
				continue
			}
			latNs := r.dstTS - m.srcTS
			if latNs < 0 {
				continue
			}
			got[m.peer][m.af]++
			results[m.peer][m.af] = append(results[m.peer][m.af], probeSample{ms: float64(latNs) / 1e6})
		}
	}

	// Build results with synthetic values: use reachability based on whether handshake existed.
	out := &pb.ProbeResults{BatchId: batchID, SourceClientId: c.clientID.Bytes()}
	for _, peer := range peers {
		pr := &pb.PeerProbeResults{DstClientId: peer.Bytes()}
		for afName, afCfg := range c.cfg.AFSettings {
			if afCfg == nil || !afCfg.Enable {
				continue
			}
			s := sent[peer][afName]
			if s == 0 {
				continue
			}
			g := got[peer][afName]
			loss := 1.0
			if s > 0 {
				loss = float64(s-g) / float64(s)
			}
			latMean := math.Inf(1)
			latStd := 0.0
			if g > 0 {
				latMean, latStd = meanStd(results[peer][afName])
			}
			pr.AfResults = append(pr.AfResults, &pb.AFProbeResult{
				AfName:        string(afName),
				LatencyMeanMs: latMean,
				LatencyStdMs:  latStd,
				PacketLoss:    loss,
				Priority:      afCfg.Priority,
			})
		}
		out.Peers = append(out.Peers, pr)
	}

	c.sendProbeResultsToAllControllers(out)
}

func (c *Client) sendProbeResultsToAllControllers(res *pb.ProbeResults) {
	b, err := proto.Marshal(res)
	if err != nil {
		return
	}
	c.log.Info("probe finished; sending results", zap.Uint64("batch_id", res.GetBatchId()), zap.Int("peers", len(res.GetPeers())))
	c.mu.Lock()
	ctrls := make([]*ControllerConn, 0, len(c.controllers))
	for _, ctrl := range c.controllers {
		ctrls = append(ctrls, ctrl)
	}
	c.mu.Unlock()
	for _, ctrl := range ctrls {
		_ = ctrl.Send(protocol.MsgProbeResults, b)
	}
}

func meanStd(samples []probeSample) (mean float64, std float64) {
	if len(samples) == 0 {
		return math.Inf(1), 0
	}
	var sum float64
	for _, s := range samples {
		sum += s.ms
	}
	mean = sum / float64(len(samples))
	var v float64
	for _, s := range samples {
		d := s.ms - mean
		v += d * d
	}
	std = math.Sqrt(v / float64(len(samples)))
	return mean, std
}

func randUint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}
