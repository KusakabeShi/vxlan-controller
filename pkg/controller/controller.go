package controller

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
	pb "vxlan-controller/proto"
)

type AFListener struct {
	AF          types.AFName
	BindAddr    netip.Addr
	Port        uint16
	TCPListener net.Listener
	UDPConn     net.PacketConn
}

type outbound struct {
	msgType protocol.MsgType
	payload []byte
}

type AFConn struct {
	AF          types.AFName
	TCPConn     net.Conn
	Session     *crypto.Session
	ConnectedAt time.Time
	RemoteIP    netip.Addr
	RemotePort  uint16
}

type ClientConn struct {
	ClientID  types.ClientID
	AFConns   map[types.AFName]*AFConn
	ActiveAF  types.AFName
	Synced    bool
	SendQueue chan outbound
}

type Controller struct {
	cfg *config.ControllerConfig
	log *zap.Logger

	privateKey   [32]byte
	controllerID types.ControllerID

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex

	state   *ControllerState
	allowed map[types.ClientID]config.PerClientConfig

	clients     map[types.ClientID]*ClientConn
	afListeners map[types.AFName]*AFListener

	udpSessionsByIndex map[uint32]*crypto.Session
	lastTAI64NByPeer   map[types.ClientID][12]byte

	newClientTimer    *time.Timer
	newClientMaxTimer *time.Timer
	topoTimer         *time.Timer
	topoMaxTimer      *time.Timer
}

func New(cfg *config.ControllerConfig, logger *zap.Logger) (*Controller, error) {
	if cfg == nil {
		return nil, errors.New("nil cfg")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	pub, err := crypto.PublicKey(cfg.PrivateKey.Key)
	if err != nil {
		return nil, err
	}
	var id types.ControllerID
	copy(id[:], pub[:])

	allowed := make(map[types.ClientID]config.PerClientConfig, len(cfg.AllowedClients))
	for _, ac := range cfg.AllowedClients {
		allowed[types.ClientID(ac.ClientID.Key)] = ac
	}

	st := &ControllerState{
		Clients:       make(map[types.ClientID]*ClientInfo),
		LatencyMatrix: make(map[types.ClientID]map[types.ClientID]*SelectedLatency),
		RouteMatrix:   make(map[types.ClientID]map[types.ClientID]*RouteEntry),
		RouteTable:    make(map[string]*RouteTableEntry),
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{
		cfg:                cfg,
		log:                logger,
		privateKey:         cfg.PrivateKey.Key,
		controllerID:       id,
		ctx:                ctx,
		cancel:             cancel,
		state:              st,
		allowed:            allowed,
		clients:            make(map[types.ClientID]*ClientConn),
		afListeners:        make(map[types.AFName]*AFListener),
		udpSessionsByIndex: make(map[uint32]*crypto.Session),
		lastTAI64NByPeer:   make(map[types.ClientID][12]byte),
	}
	return c, nil
}

func (c *Controller) ControllerID() types.ControllerID { return c.controllerID }

func (c *Controller) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	for afName, af := range c.cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		afn := afName
		addr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(af.BindAddr.Addr, af.CommunicationPort))
		ln, err := listenTCPRetry(addr, 3*time.Second)
		if err != nil {
			return fmt.Errorf("listen tcp %s: %w", addr.AddrPort().String(), err)
		}
		udp, err := listenPacketRetry("udp", addr.AddrPort().String(), 3*time.Second)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("listen udp %s: %w", addr.AddrPort().String(), err)
		}
		l := &AFListener{AF: afn, BindAddr: af.BindAddr.Addr, Port: af.CommunicationPort, TCPListener: ln, UDPConn: udp}
		c.mu.Lock()
		c.afListeners[afn] = l
		c.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.tcpAcceptLoop(runCtx, l)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.udpReadLoop(runCtx, l)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.offlineChecker(runCtx)
	}()

	<-runCtx.Done()
	c.cancel()

	c.mu.Lock()
	for _, l := range c.afListeners {
		_ = l.TCPListener.Close()
		_ = l.UDPConn.Close()
	}
	for _, cl := range c.clients {
		for _, afc := range cl.AFConns {
			_ = afc.TCPConn.Close()
		}
	}
	c.mu.Unlock()

	wg.Wait()
	return ctx.Err()
}

func listenTCPRetry(addr *net.TCPAddr, maxWait time.Duration) (*net.TCPListener, error) {
	deadline := time.Now().Add(maxWait)
	backoff := 50 * time.Millisecond
	for {
		ln, err := net.ListenTCP("tcp", addr)
		if err == nil {
			return ln, nil
		}
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

func listenPacketRetry(network, addr string, maxWait time.Duration) (net.PacketConn, error) {
	deadline := time.Now().Add(maxWait)
	backoff := 50 * time.Millisecond
	for {
		pc, err := net.ListenPacket(network, addr)
		if err == nil {
			return pc, nil
		}
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

func (c *Controller) tcpAcceptLoop(ctx context.Context, l *AFListener) {
	for {
		conn, err := l.TCPListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				c.log.Warn("accept failed", zap.String("af", string(l.AF)), zap.Error(err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
		}
		go c.handleTCPConn(ctx, l.AF, conn)
	}
}

func (c *Controller) handleTCPConn(ctx context.Context, af types.AFName, conn net.Conn) {
	defer conn.Close()

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	allowed := func(peerStaticPub [32]byte) bool {
		_, ok := c.allowed[types.ClientID(peerStaticPub)]
		return ok
	}

	checkTS := func(peer types.ClientID, ts [12]byte) bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		prev, ok := c.lastTAI64NByPeer[peer]
		if ok && bytesLEOrEqual(ts, prev) {
			return false
		}
		c.lastTAI64NByPeer[peer] = ts
		return true
	}

	initType, initPayload, err := protocol.ReadTCPMessage(conn, nil)
	if err != nil {
		c.log.Warn("read handshake init failed", zap.Error(err))
		return
	}
	if initType != protocol.MsgHandshakeInit {
		c.log.Warn("unexpected first msg", zap.Uint8("msg_type", uint8(initType)))
		return
	}
	respPayload, sess, info, err := crypto.HandshakeRespond(c.privateKey, initPayload, allowed, checkTS, time.Now())
	if err != nil {
		c.log.Warn("handshake respond failed", zap.Error(err))
		return
	}
	if err := protocol.WriteTCPMessage(conn, nil, protocol.MsgHandshakeResp, respPayload); err != nil {
		c.log.Warn("write handshake resp failed", zap.Error(err))
		return
	}

	clientID := sess.PeerID
	if info.PeerID != clientID {
		c.log.Warn("peer id mismatch", zap.String("peer", clientID.String()))
	}

	msgType, plain, err := protocol.ReadTCPMessage(conn, sess)
	if err != nil {
		c.log.Warn("read client register failed", zap.Error(err))
		return
	}
	if msgType != protocol.MsgClientRegister {
		c.log.Warn("unexpected msg after handshake", zap.Uint8("msg_type", uint8(msgType)))
		return
	}
	var reg pb.ClientRegister
	if err := proto.Unmarshal(plain, &reg); err != nil {
		c.log.Warn("unmarshal client register failed", zap.Error(err))
		return
	}

	remoteIP, remotePort, err := splitRemote(conn.RemoteAddr())
	if err != nil {
		c.log.Warn("parse remote addr failed", zap.Error(err))
		return
	}

	c.mu.Lock()
	c.udpSessionsByIndex[sess.LocalIndex] = sess

	cl := c.clients[clientID]
	if cl == nil {
		cl = &ClientConn{
			ClientID:  clientID,
			AFConns:   make(map[types.AFName]*AFConn),
			SendQueue: make(chan outbound, 256),
		}
		c.clients[clientID] = cl
		go c.clientSendLoop(c.ctx, clientID, cl.SendQueue)
	}
	cl.AFConns[af] = &AFConn{
		AF:          af,
		TCPConn:     conn,
		Session:     sess,
		ConnectedAt: time.Now(),
		RemoteIP:    remoteIP,
		RemotePort:  remotePort,
	}
	c.updateClientInfoLocked(clientID, af, remoteIP, remotePort, &reg)

	c.noteClientChangeLocked()

	c.ensureActiveAFLocked(cl)
	if cl.ActiveAF == af {
		c.enqueueFullStateLocked(clientID, true)
	}
	c.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		msgType, plain, err := protocol.ReadTCPMessage(conn, sess)
		if err != nil {
			c.log.Info("tcp conn closed", zap.String("client", clientID.String()), zap.String("af", string(af)), zap.Error(err))
			c.onDisconnect(clientID, af, sess.LocalIndex)
			return
		}

		switch msgType {
		case protocol.MsgRouteUpdate:
			var batch pb.RouteUpdateBatch
			if err := proto.Unmarshal(plain, &batch); err != nil {
				c.log.Warn("unmarshal route update failed", zap.Error(err))
				continue
			}
			c.handleRouteUpdate(clientID, &batch)
		case protocol.MsgProbeResults:
			var res pb.ProbeResults
			if err := proto.Unmarshal(plain, &res); err != nil {
				c.log.Warn("unmarshal probe results failed", zap.Error(err))
				continue
			}
			c.handleProbeResults(clientID, &res)
		default:
			c.log.Warn("unknown msg type", zap.Uint8("msg_type", uint8(msgType)))
		}
	}
}

func (c *Controller) updateClientInfoLocked(clientID types.ClientID, af types.AFName, remoteIP netip.Addr, remotePort uint16, reg *pb.ClientRegister) {
	now := time.Now()
	info := c.state.Clients[clientID]
	if info == nil {
		info = &ClientInfo{ClientID: clientID, Endpoints: make(map[types.AFName]*Endpoint)}
		c.state.Clients[clientID] = info
	}
	info.LastSeen = now
	if ac, ok := c.allowed[clientID]; ok {
		info.AdditionalCost = ac.AdditionalCost
	}

	ep := info.Endpoints[af]
	if ep == nil {
		ep = &Endpoint{}
		info.Endpoints[af] = ep
	}
	ep.IP = remoteIP
	ep.CommunicationPort = remotePort

	for _, a := range reg.GetAfs() {
		if a == nil {
			continue
		}
		if types.AFName(a.GetAfName()) != af {
			continue
		}
		ep.ProbePort = uint16(a.GetProbePort())
		ep.VxlanDstPort = uint16(a.GetVxlanDstport())
		ep.Priority = a.GetPriority()
	}
}

func (c *Controller) noteClientChangeLocked() {
	c.state.LastClientChange = time.Now()

	resetTimer := func(t **time.Timer, d time.Duration, f func()) {
		if *t == nil {
			*t = time.AfterFunc(d, f)
			return
		}
		if !(*t).Stop() {
			select {
			case <-(*t).C:
			default:
			}
		}
		(*t).Reset(d)
	}

	if c.newClientMaxTimer == nil {
		c.newClientMaxTimer = time.AfterFunc(c.cfg.SyncNewClientDebounceMax.D, func() { c.fireProbeRequest() })
	}
	resetTimer(&c.newClientTimer, c.cfg.SyncNewClientDebounce.D, func() { c.fireProbeRequest() })
}

func (c *Controller) fireProbeRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.newClientTimer != nil {
		c.newClientTimer.Stop()
		c.newClientTimer = nil
	}
	if c.newClientMaxTimer != nil {
		c.newClientMaxTimer.Stop()
		c.newClientMaxTimer = nil
	}

	req := &pb.ControllerProbeRequest{
		BatchId:           randUint64(),
		ProbeTimes:        uint32(c.cfg.Probing.ProbeTimes),
		InProbeIntervalMs: uint32(c.cfg.Probing.InProbeIntervalMs),
		ProbeTimeoutMs:    uint32(c.cfg.Probing.ProbeTimeoutMs),
	}
	c.log.Info("fire probe request", zap.Uint64("batch_id", req.BatchId), zap.Uint32("probe_times", req.ProbeTimes))
	b, _ := proto.Marshal(req)
	for id := range c.clients {
		c.enqueueLocked(id, outbound{msgType: protocol.MsgControllerProbeRequest, payload: b})
	}
}

func randUint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

func (c *Controller) ensureActiveAFLocked(cl *ClientConn) {
	if cl == nil {
		return
	}
	if cl.ActiveAF != "" {
		// Ensure still exists.
		if _, ok := cl.AFConns[cl.ActiveAF]; ok {
			return
		}
		cl.ActiveAF = ""
	}
	var best *AFConn
	var bestAF types.AFName
	for af, ac := range cl.AFConns {
		if best == nil || ac.ConnectedAt.Before(best.ConnectedAt) {
			best = ac
			bestAF = af
		}
	}
	cl.ActiveAF = bestAF
}

func (c *Controller) onDisconnect(clientID types.ClientID, af types.AFName, localIndex uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.udpSessionsByIndex, localIndex)

	cl := c.clients[clientID]
	if cl == nil {
		return
	}
	delete(cl.AFConns, af)
	oldActive := cl.ActiveAF
	c.ensureActiveAFLocked(cl)
	if oldActive != "" && oldActive != cl.ActiveAF && cl.ActiveAF != "" {
		// Active switched, full sync.
		cl.Synced = false
		c.enqueueFullStateLocked(clientID, true)
	}
	c.noteClientChangeLocked()
}

func (c *Controller) clientSendLoop(ctx context.Context, clientID types.ClientID, q <-chan outbound) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-q:
			if !ok {
				return
			}
			var conn net.Conn
			var sess *crypto.Session
			c.mu.Lock()
			cl := c.clients[clientID]
			if cl != nil {
				c.ensureActiveAFLocked(cl)
				if ac := cl.AFConns[cl.ActiveAF]; ac != nil {
					conn = ac.TCPConn
					sess = ac.Session
				}
			}
			c.mu.Unlock()
			if conn == nil || sess == nil {
				continue
			}
			if err := protocol.WriteTCPMessage(conn, sess, msg.msgType, msg.payload); err != nil {
				c.log.Warn("send failed", zap.String("client", clientID.String()), zap.Error(err))
			}
		}
	}
}

func (c *Controller) enqueueLocked(clientID types.ClientID, msg outbound) {
	cl := c.clients[clientID]
	if cl == nil {
		return
	}
	c.enqueueClientLocked(cl, msg, clientID)
}

func (c *Controller) enqueueClientLocked(cl *ClientConn, msg outbound, clientID types.ClientID) {
	select {
	case cl.SendQueue <- msg:
	default:
		cl.Synced = false
		for {
			select {
			case <-cl.SendQueue:
			default:
				goto drained
			}
		}
	drained:
		c.enqueueFullStateLocked(clientID, false)
	}
}

func (c *Controller) enqueueFullStateLocked(clientID types.ClientID, initial bool) {
	snap := c.serializeStateLocked()
	var msgType protocol.MsgType
	var payload []byte
	if initial {
		msgType = protocol.MsgControllerState
		payload, _ = proto.Marshal(snap)
	} else {
		msgType = protocol.MsgControllerStateUpdate
		u := &pb.ControllerStateUpdate{FullReplace: true, State: snap}
		payload, _ = proto.Marshal(u)
	}
	cl := c.clients[clientID]
	if cl == nil {
		return
	}
	cl.Synced = true
	select {
	case cl.SendQueue <- outbound{msgType: msgType, payload: payload}:
	default:
		// Can't even enqueue snapshot; mark unsynced and drop.
		cl.Synced = false
	}
}

func (c *Controller) serializeStateLocked() *pb.ControllerState {
	state := &pb.ControllerState{
		ControllerId:           c.controllerID[:],
		LastClientChangeUnixNs: c.state.LastClientChange.UnixNano(),
	}

	clientCount := 0
	for _, cl := range c.clients {
		if len(cl.AFConns) > 0 {
			clientCount++
		}
	}
	state.ClientCount = uint32(clientCount)

	for id, info := range c.state.Clients {
		ci := &pb.ClientInfo{
			ClientId:       id.Bytes(),
			LastSeenUnixNs: info.LastSeen.UnixNano(),
			AdditionalCost: info.AdditionalCost,
		}
		for af, ep := range info.Endpoints {
			if ep == nil || !ep.IP.IsValid() {
				continue
			}
			ci.Endpoints = append(ci.Endpoints, &pb.ClientEndpoint{
				AfName:            string(af),
				Ip:                types.NetIPToBytes(ep.IP),
				ProbePort:         uint32(ep.ProbePort),
				CommunicationPort: uint32(ep.CommunicationPort),
				VxlanDstport:      uint32(ep.VxlanDstPort),
				Priority:          ep.Priority,
			})
		}
		state.Clients = append(state.Clients, ci)
	}

	for src, row := range c.state.LatencyMatrix {
		r := &pb.LatencyRow{SrcClientId: src.Bytes()}
		for dst, ent := range row {
			if ent == nil {
				continue
			}
			r.Entries = append(r.Entries, &pb.SelectedLatency{
				DstClientId: dst.Bytes(),
				AfName:      string(ent.AF),
				LatencyMs:   ent.LatencyMs,
			})
		}
		state.LatencyMatrix = append(state.LatencyMatrix, r)
	}

	for src, row := range c.state.RouteMatrix {
		r := &pb.RouteRow{SrcClientId: src.Bytes()}
		for dst, ent := range row {
			re := &pb.RouteEntry{
				DstClientId: dst.Bytes(),
			}
			if ent != nil {
				re.NexthopClientId = ent.NextHop.Bytes()
				re.AfName = string(ent.AF)
			}
			r.Entries = append(r.Entries, re)
		}
		state.RouteMatrix = append(state.RouteMatrix, r)
	}

	now := time.Now()
	for _, rte := range c.state.RouteTable {
		e := &pb.RouteTableEntry{
			Mac: rte.MAC[:],
			Ip:  types.NetIPToBytes(rte.IP),
		}
		for owner, exp := range rte.Owners {
			if exp.Before(now) {
				continue
			}
			e.Owners = append(e.Owners, &pb.RouteOwner{ClientId: owner.Bytes(), ExpireUnixNs: exp.UnixNano()})
		}
		state.RouteTable = append(state.RouteTable, e)
	}
	return state
}

func (c *Controller) handleRouteUpdate(clientID types.ClientID, batch *pb.RouteUpdateBatch) {
	now := time.Now()
	// Keep route ownership alive for a reasonable window. Actual offline removal is
	// driven by connection/LastSeen tracking in offlineChecker.
	exp := now.Add(10 * time.Minute)

	c.mu.Lock()
	defer c.mu.Unlock()

	info := c.state.Clients[clientID]
	if info != nil {
		info.LastSeen = now
	}

	changed := false
	for _, u := range batch.GetUpdates() {
		if u == nil || u.Entry == nil || len(u.Entry.Mac) != 6 {
			continue
		}
		var mac [6]byte
		copy(mac[:], u.Entry.Mac)
		ip, err := types.BytesToNetIP(u.Entry.Ip)
		if err != nil {
			continue
		}
		key := routeKey(mac, ip)
		e := c.state.RouteTable[key]
		if e == nil {
			e = &RouteTableEntry{MAC: mac, IP: ip, Owners: make(map[types.ClientID]time.Time)}
			c.state.RouteTable[key] = e
		}
		switch u.GetOp() {
		case pb.RouteUpdate_OP_ADD:
			e.Owners[clientID] = exp
			changed = true
		case pb.RouteUpdate_OP_DEL:
			delete(e.Owners, clientID)
			changed = true
		default:
		}
		if len(e.Owners) == 0 {
			delete(c.state.RouteTable, key)
		}
	}
	if changed {
		c.pushUpdateLocked()
	}
}

func (c *Controller) handleProbeResults(clientID types.ClientID, res *pb.ProbeResults) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log.Info("probe results received", zap.String("client", clientID.String()), zap.Uint64("batch_id", res.GetBatchId()), zap.Int("peers", len(res.GetPeers())))
	now := time.Now()
	info := c.state.Clients[clientID]
	if info != nil {
		info.LastSeen = now
	}

	src := clientID
	if c.state.LatencyMatrix[src] == nil {
		c.state.LatencyMatrix[src] = make(map[types.ClientID]*SelectedLatency)
	}
	for _, peer := range res.GetPeers() {
		if peer == nil || len(peer.DstClientId) != 32 {
			continue
		}
		var dstID types.ClientID
		copy(dstID[:], peer.DstClientId)
		bestPri := int32(math.MaxInt32)
		bestLat := math.Inf(1)
		bestAF := types.AFName("")
		for _, af := range peer.GetAfResults() {
			if af == nil {
				continue
			}
			lat := af.GetLatencyMeanMs()
			pri := af.GetPriority()
			if math.IsInf(lat, 1) || lat <= 0 {
				continue
			}
			if pri < bestPri || (pri == bestPri && lat < bestLat) {
				bestPri = pri
				bestLat = lat
				bestAF = types.AFName(af.GetAfName())
			}
		}
		if bestAF == "" {
			c.state.LatencyMatrix[src][dstID] = &SelectedLatency{LatencyMs: math.Inf(1), AF: ""}
		} else {
			c.state.LatencyMatrix[src][dstID] = &SelectedLatency{LatencyMs: bestLat, AF: bestAF}
		}
	}

	c.resetTopologyDebounceLocked()
}

func (c *Controller) resetTopologyDebounceLocked() {
	resetTimer := func(t **time.Timer, d time.Duration, f func()) {
		if *t == nil {
			*t = time.AfterFunc(d, f)
			return
		}
		if !(*t).Stop() {
			select {
			case <-(*t).C:
			default:
			}
		}
		(*t).Reset(d)
	}
	if c.topoMaxTimer == nil {
		c.topoMaxTimer = time.AfterFunc(c.cfg.TopologyUpdateDebounceMax.D, func() { c.fireTopologyUpdate() })
	}
	resetTimer(&c.topoTimer, c.cfg.TopologyUpdateDebounce.D, func() { c.fireTopologyUpdate() })
}

func (c *Controller) fireTopologyUpdate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.topoTimer != nil {
		c.topoTimer.Stop()
		c.topoTimer = nil
	}
	if c.topoMaxTimer != nil {
		c.topoMaxTimer.Stop()
		c.topoMaxTimer = nil
	}
	c.state.RouteMatrix = ComputeRouteMatrix(c.state.Clients, c.state.LatencyMatrix)
	c.pushUpdateLocked()
}

func (c *Controller) pushUpdateLocked() {
	snap := c.serializeStateLocked()
	up := &pb.ControllerStateUpdate{FullReplace: true, State: snap}
	b, _ := proto.Marshal(up)
	for id, cl := range c.clients {
		if !cl.Synced {
			continue
		}
		c.enqueueClientLocked(cl, outbound{msgType: protocol.MsgControllerStateUpdate, payload: b}, id)
	}
}

func (c *Controller) udpReadLoop(ctx context.Context, l *AFListener) {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := l.UDPConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		msgType, payload, peerID, err := protocol.ReadUDPPacket(pkt, func(idx uint32) *crypto.Session {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.udpSessionsByIndex[idx]
		})
		if err != nil {
			continue
		}
		if msgType != protocol.MsgMulticastForward {
			continue
		}
		var f pb.MulticastForward
		if err := proto.Unmarshal(payload, &f); err != nil {
			continue
		}
		c.relayBroadcast(peerID, f.GetFrame())
	}
}

func (c *Controller) relayBroadcast(source types.ClientID, frame []byte) {
	if len(frame) == 0 {
		return
	}
	msg := &pb.MulticastDeliver{SourceClientId: source.Bytes(), Frame: frame}
	b, _ := proto.Marshal(msg)

	c.mu.Lock()
	defer c.mu.Unlock()

	for id, cl := range c.clients {
		if id.Equal(source) {
			continue
		}
		c.ensureActiveAFLocked(cl)
		ac := cl.AFConns[cl.ActiveAF]
		if ac == nil || ac.Session == nil {
			continue
		}
		l := c.afListeners[cl.ActiveAF]
		if l == nil {
			continue
		}
		dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ac.RemoteIP, ac.RemotePort))
		_ = protocol.WriteUDPPacket(l.UDPConn, dst, ac.Session, protocol.MsgMulticastDeliver, b)
	}
}

func (c *Controller) offlineChecker(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		now := time.Now()
		changed := false
		for id, info := range c.state.Clients {
			// Treat clients with an active TCP connection as online, even if they haven't
			// produced probe results recently (e.g. when probe is event-driven).
			if cl := c.clients[id]; cl != nil && len(cl.AFConns) > 0 {
				info.LastSeen = now
				continue
			}
			if now.Sub(info.LastSeen) > c.cfg.ClientOfflineTimeout.D {
				delete(c.state.Clients, id)
				delete(c.state.LatencyMatrix, id)
				delete(c.state.RouteMatrix, id)
				for src := range c.state.LatencyMatrix {
					delete(c.state.LatencyMatrix[src], id)
				}
				for src := range c.state.RouteMatrix {
					delete(c.state.RouteMatrix[src], id)
				}
				for k, rte := range c.state.RouteTable {
					delete(rte.Owners, id)
					if len(rte.Owners) == 0 {
						delete(c.state.RouteTable, k)
					}
				}
				changed = true
			}
		}
		if changed {
			c.state.RouteMatrix = ComputeRouteMatrix(c.state.Clients, c.state.LatencyMatrix)
			c.pushUpdateLocked()
		}
		c.mu.Unlock()
	}
}

func routeKey(mac [6]byte, ip netip.Addr) string {
	if ip.IsValid() {
		return fmt.Sprintf("%x|%s", mac, ip.String())
	}
	return fmt.Sprintf("%x|", mac)
}

func splitRemote(a net.Addr) (netip.Addr, uint16, error) {
	switch v := a.(type) {
	case *net.TCPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, 0, errors.New("invalid ip")
		}
		return addr.Unmap(), uint16(v.Port), nil
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, 0, errors.New("invalid ip")
		}
		return addr.Unmap(), uint16(v.Port), nil
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.Addr{}, 0, err
		}
		return ap.Addr(), ap.Port(), nil
	}
}

func bytesLEOrEqual(a, b [12]byte) bool {
	// Compare as big-endian bytes (TAI64N is BE), a <= b
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
