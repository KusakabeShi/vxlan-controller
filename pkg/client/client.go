package client

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/ntp"
	"vxlan-controller/pkg/types"
	pb "vxlan-controller/proto"
)

type ControllerID = types.ControllerID

type Client struct {
	cfg *config.ClientConfig
	log *zap.Logger

	privateKey [32]byte
	clientID   types.ClientID

	ntpOffset ntp.Offset

	ctx    context.Context
	cancel context.CancelFunc

	mu                  sync.Mutex
	controllers         map[types.ControllerID]*ControllerConn
	controllerEndpoints map[types.ControllerID]map[types.AFName]netip.AddrPort
	authority           *types.ControllerID

	afRuntime map[types.AFName]*AFRuntime

	bridgeName string
	vxlanDevs  map[types.AFName]*VxlanDev
	tap        *TapDevice

	tapInjectCh  chan []byte
	fdbNotifyCh  chan struct{}
	authNotifyCh chan struct{}

	currentFDB   map[fdbKey]fdbEntry
	currentNeigh map[neighKey]struct{}

	localRoutes map[string]*pb.MacIpEntry

	probeMu     sync.Mutex
	probeRespCh map[uint64]chan probeResponse

	pendingProbe map[types.ControllerID]*pb.ControllerProbeRequest
}

func New(cfg *config.ClientConfig, logger *zap.Logger) (*Client, error) {
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
	cid := types.ClientID(pub)
	ctx, cancel := context.WithCancel(context.Background())
	endpoints := make(map[types.ControllerID]map[types.AFName]netip.AddrPort)
	for afName, af := range cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		for _, ce := range af.Controllers {
			var ctrl types.ControllerID
			copy(ctrl[:], ce.PubKey.Key[:])
			m := endpoints[ctrl]
			if m == nil {
				m = make(map[types.AFName]netip.AddrPort)
				endpoints[ctrl] = m
			}
			m[afName] = ce.Addr.Addr
		}
	}

	return &Client{
		cfg:                 cfg,
		log:                 logger,
		privateKey:          cfg.PrivateKey.Key,
		clientID:            cid,
		ctx:                 ctx,
		cancel:              cancel,
		controllers:         make(map[types.ControllerID]*ControllerConn),
		controllerEndpoints: endpoints,
		afRuntime:           make(map[types.AFName]*AFRuntime),
		bridgeName:          cfg.BridgeName,
		vxlanDevs:           make(map[types.AFName]*VxlanDev),
		tapInjectCh:         make(chan []byte, 1024),
		fdbNotifyCh:         make(chan struct{}, 1),
		authNotifyCh:        make(chan struct{}, 1),
		currentFDB:          make(map[fdbKey]fdbEntry),
		currentNeigh:        make(map[neighKey]struct{}),
		localRoutes:         make(map[string]*pb.MacIpEntry),
		probeRespCh:         make(map[uint64]chan probeResponse),
		pendingProbe:        make(map[types.ControllerID]*pb.ControllerProbeRequest),
	}, nil
}

func (c *Client) ClientID() types.ClientID { return c.clientID }

func (c *Client) Now() time.Time { return time.Now().Add(c.ntpOffset.Load()) }

func (c *Client) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go ntp.SyncLoop(runCtx, c.log.Named("ntp"), c.cfg.NTPServers, c.cfg.NTPResyncInterval.D, &c.ntpOffset)

	if err := c.initDevices(); err != nil {
		return err
	}

	// Build per-AF runtime sockets.
	for afName, af := range c.cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		rt, err := NewAFRuntime(afName, af.BindAddr.Addr, af.CommunicationPort, af.ProbePort)
		if err != nil {
			return err
		}
		c.afRuntime[afName] = rt
		go c.commUDPReadLoop(runCtx, afName, rt)
		go c.probeUDPReadLoop(runCtx, afName, rt)
	}

	go c.tapReadLoop(runCtx)
	go c.tapWriteLoop(runCtx)
	go c.fdbReconcileLoop(runCtx)
	go c.authoritySelectLoop(runCtx)
	go c.neighWatchLoop(runCtx)
	go c.apiServerLoop(runCtx)

	// Start per-controller, per-AF TCP loops.
	c.startControllerLoops(runCtx)

	<-runCtx.Done()
	c.cancel()
	_ = c.tap.Close()
	for _, rt := range c.afRuntime {
		_ = rt.Close()
	}
	return ctx.Err()
}

func (c *Client) startControllerLoops(ctx context.Context) {
	seen := make(map[types.ControllerID]struct{})
	for _, af := range c.cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		for _, ce := range af.Controllers {
			var ctrlID types.ControllerID
			copy(ctrlID[:], ce.PubKey.Key[:])
			seen[ctrlID] = struct{}{}
		}
	}
	for ctrlID := range seen {
		c.controllers[ctrlID] = &ControllerConn{
			ControllerID: ctrlID,
			AFConns:      make(map[types.AFName]*ClientAFConn),
		}
	}
	for afName, af := range c.cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		for _, ce := range af.Controllers {
			var ctrlID types.ControllerID
			copy(ctrlID[:], ce.PubKey.Key[:])
			addr := ce.Addr.Addr
			go c.tcpConnLoop(ctx, ctrlID, afName, addr, ce.PubKey.Key)
		}
	}
}

// Called by API: update bind_addr for AF.
func (c *Client) UpdateBindAddr(afName types.AFName, newAddr netip.Addr) error {
	c.mu.Lock()
	afCfg := c.cfg.AFSettings[afName]
	if afCfg == nil {
		c.mu.Unlock()
		return fmt.Errorf("unknown af %q", afName)
	}
	afCfg.BindAddr.Addr = newAddr
	c.mu.Unlock()

	// Recreate sockets to bind new address; force reconnect.
	rt := c.afRuntime[afName]
	if rt != nil {
		_ = rt.Close()
	}
	nrt, err := NewAFRuntime(afName, newAddr, afCfg.CommunicationPort, afCfg.ProbePort)
	if err != nil {
		return err
	}
	c.afRuntime[afName] = nrt

	go c.commUDPReadLoop(c.ctx, afName, nrt)
	go c.probeUDPReadLoop(c.ctx, afName, nrt)

	// Update vxlan local.
	if vx := c.vxlanDevs[afName]; vx != nil {
		_ = vx.UpdateLocal(newAddr)
	}

	// Force reconnect TCP sessions on that AF.
	c.mu.Lock()
	for _, ctrl := range c.controllers {
		ctrl.mu.Lock()
		ac := ctrl.AFConns[afName]
		ctrl.mu.Unlock()
		if ac != nil && ac.TCPConn != nil {
			_ = ac.TCPConn.Close()
		}
	}
	c.mu.Unlock()
	return nil
}

func ensureDir(path string) error {
	st, err := os.Stat(path)
	if err == nil && st.IsDir() {
		return nil
	}
	return os.MkdirAll(path, 0o755)
}
