package controller

import (
	"net"
	"net/netip"
	"time"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	"github.com/vishvananda/netlink"
)

// resolveInitialBindAddr runs addr selection once for a controller AF.
func (c *Controller) resolveInitialBindAddr(af types.AFName) {
	afCfg := c.Config.AFSettings[af]
	engine := c.addrEngines[af]
	if engine == nil {
		return
	}

	addrs := filter.GetInterfaceAddrs(afCfg.AutoIPInterface, string(af))
	selected := engine.Select(addrs, "", afCfg.AutoIPInterface)
	if selected == "" {
		vlog.Warnf("[AddrWatch] AF=%s: no IP found on interface %s at startup, will retry on events", af, afCfg.AutoIPInterface)
		return
	}

	addr, err := netip.ParseAddr(selected)
	if err != nil {
		vlog.Errorf("[AddrWatch] AF=%s: Lua returned invalid IP %q: %v", af, selected, err)
		return
	}

	afCfg.BindAddr = addr
	vlog.Infof("[AddrWatch] AF=%s: initial bind_addr resolved to %s from interface %s", af, addr, afCfg.AutoIPInterface)
}

// addrWatchLoop monitors netlink address and link events for all AFs with AutoIPInterface.
func (c *Controller) addrWatchLoop() {
	ifaceAFs := make(map[string][]types.AFName)
	for af, afCfg := range c.Config.AFSettings {
		if afCfg.AutoIPInterface != "" {
			ifaceAFs[afCfg.AutoIPInterface] = append(ifaceAFs[afCfg.AutoIPInterface], af)
		}
	}
	if len(ifaceAFs) == 0 {
		return
	}

	for iface, afs := range ifaceAFs {
		vlog.Infof("[AddrWatch] monitoring interface %s for AFs: %v", iface, afs)
	}

	addrCh := make(chan netlink.AddrUpdate)
	addrDone := make(chan struct{})
	defer close(addrDone)

	if err := netlink.AddrSubscribe(addrCh, addrDone); err != nil {
		vlog.Errorf("[AddrWatch] netlink addr subscribe error: %v", err)
		return
	}

	linkCh := make(chan netlink.LinkUpdate)
	linkDone := make(chan struct{})
	defer close(linkDone)

	if err := netlink.LinkSubscribe(linkCh, linkDone); err != nil {
		vlog.Errorf("[AddrWatch] netlink link subscribe error: %v", err)
		return
	}

	debounceTimers := make(map[string]*time.Timer)
	debounceCh := make(chan string, 16)

	triggerDebounce := func(ifaceName string) {
		if t, ok := debounceTimers[ifaceName]; ok {
			t.Reset(time.Second)
		} else {
			debounceTimers[ifaceName] = time.AfterFunc(time.Second, func() {
				select {
				case debounceCh <- ifaceName:
				default:
				}
			})
		}
	}

	linkIndexToName := make(map[int]string)
	for ifaceName := range ifaceAFs {
		if link, err := netlink.LinkByName(ifaceName); err == nil {
			linkIndexToName[link.Attrs().Index] = ifaceName
		}
	}

	for {
		select {
		case update, ok := <-addrCh:
			if !ok {
				return
			}
			vlog.Debugf("[AddrWatch] addr event: linkIndex=%d newAddr=%v ip=%v", update.LinkIndex, update.NewAddr, update.LinkAddress.IP)
			ifaceName, found := linkIndexToName[update.LinkIndex]
			if !found {
				for name := range ifaceAFs {
					if link, err := netlink.LinkByName(name); err == nil {
						linkIndexToName[link.Attrs().Index] = name
						if link.Attrs().Index == update.LinkIndex {
							ifaceName = name
							found = true
						}
					}
				}
			}
			if found {
				triggerDebounce(ifaceName)
			}

		case update, ok := <-linkCh:
			if !ok {
				return
			}
			name := update.Attrs().Name
			if _, monitored := ifaceAFs[name]; monitored {
				linkIndexToName[update.Attrs().Index] = name
				triggerDebounce(name)
			}

		case ifaceName := <-debounceCh:
			c.handleAddrChange(ifaceName, ifaceAFs[ifaceName])

		case <-c.ctx.Done():
			for _, t := range debounceTimers {
				t.Stop()
			}
			return
		}
	}
}

// handleAddrChange processes an address change on an interface for the given AFs.
func (c *Controller) handleAddrChange(ifaceName string, afs []types.AFName) {
	for _, af := range afs {
		engine := c.addrEngines[af]
		if engine == nil {
			continue
		}

		afCfg := c.Config.AFSettings[af]
		addrs := filter.GetInterfaceAddrs(ifaceName, string(af))

		prevIP := afCfg.BindAddr.String()
		if !afCfg.BindAddr.IsValid() {
			prevIP = ""
		}

		selected := engine.Select(addrs, prevIP, ifaceName)
		if selected == "" {
			vlog.Debugf("[AddrWatch] AF=%s: no valid IP on %s, ignoring", af, ifaceName)
			continue
		}

		newAddr, err := netip.ParseAddr(selected)
		if err != nil {
			vlog.Errorf("[AddrWatch] AF=%s: Lua returned invalid IP %q: %v", af, selected, err)
			continue
		}

		if afCfg.BindAddr == newAddr {
			continue
		}

		oldAddr := afCfg.BindAddr
		vlog.Infof("[AddrWatch] AF=%s: detected IP change on %s: %s -> %s", af, ifaceName, prevIP, newAddr)

		// Update config
		afCfg.BindAddr = newAddr

		// Rebind listeners
		c.rebindAFListener(af, oldAddr, newAddr)
	}
}

// rebindAFListener closes the old listener and starts a new one on the new address.
func (c *Controller) rebindAFListener(af types.AFName, oldAddr, newAddr netip.Addr) {
	afCfg := c.Config.AFSettings[af]

	// Close old listener
	c.mu.Lock()
	oldAL := c.afListeners[af]
	if oldAL != nil {
		oldAL.TCPListener.Close()
		oldAL.UDPConn.Close()
		delete(c.afListeners, af)
	}
	c.mu.Unlock()

	// Retry bind with backoff (IPv6 DAD may delay address availability)
	bindStr := netip.AddrPortFrom(newAddr, afCfg.CommunicationPort).String()
	var tcpListener net.Listener
	var udpConn *net.UDPConn
	var err error

	for attempt := 0; attempt < 10; attempt++ {
		tcpListener, err = net.Listen("tcp", bindStr)
		if err == nil {
			udpAddr, _ := net.ResolveUDPAddr("udp", bindStr)
			udpConn, err = net.ListenUDP("udp", udpAddr)
			if err == nil {
				break
			}
			tcpListener.Close()
		}
		select {
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		case <-c.ctx.Done():
			return
		}
	}
	if err != nil {
		vlog.Errorf("[AddrWatch] AF=%s: failed to rebind on %s after retries: %v", af, bindStr, err)
		return
	}

	al := &AFListener{
		AF:          af,
		BindAddr:    newAddr,
		Port:        afCfg.CommunicationPort,
		TCPListener: tcpListener,
		UDPConn:     udpConn,
		UDPSessions: crypto.NewSessionManager(),
	}

	c.mu.Lock()
	c.afListeners[af] = al
	c.mu.Unlock()

	vlog.Infof("[AddrWatch] AF=%s: rebound listeners on %s", af, bindStr)

	go c.tcpAcceptLoop(al)
	go c.udpReadLoop(al)

	// All existing client connections on this AF will fail on their own
	// (TCP reads/writes will error out). Clients will reconnect via tcpConnLoop.
}
