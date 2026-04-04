package client

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"vxlan-controller/pkg/types"
)

type VxlanDev struct {
	AF       types.AFName
	Name     string
	VNI      uint32
	MTU      int
	BindAddr netip.Addr
	DstPort  uint16
	SrcPortStart uint16
	SrcPortEnd   uint16

	BridgeName string
	Log *zap.Logger
}

func (v *VxlanDev) UpdateLocal(newAddr netip.Addr) error {
	if v == nil {
		return nil
	}
	v.BindAddr = newAddr
	// ip link set <dev> type vxlan local <addr>
	_, err := run("ip", "link", "set", v.Name, "type", "vxlan", "local", newAddr.String())
	if err != nil && v.Log != nil {
		v.Log.Warn("vxlan update local failed", zap.String("dev", v.Name), zap.Error(err))
	}
	return err
}

func (c *Client) initDevices() error {
	if _, err := run("ip", "link", "add", c.bridgeName, "type", "bridge"); err != nil {
		// already exists is ok
	}
	if _, err := run("ip", "link", "set", c.bridgeName, "up"); err != nil {
		return err
	}

	for afName, af := range c.cfg.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		// vxlan device create
		args := []string{
			"link", "add", af.VxlanName, "type", "vxlan",
			"id", strconv.FormatUint(uint64(af.VxlanVNI), 10),
			"local", af.BindAddr.Addr.String(),
			"ttl", "255",
			"dstport", strconv.Itoa(int(af.VxlanDstPort)),
			"srcport", strconv.Itoa(int(af.VxlanSrcPortStart)), strconv.Itoa(int(af.VxlanSrcPortEnd)),
			"nolearning",
		}
		if _, err := run("ip", args...); err != nil {
			// ignore if exists
		}
		if af.VxlanMTU > 0 {
			_, _ = run("ip", "link", "set", af.VxlanName, "mtu", strconv.Itoa(af.VxlanMTU))
		}
		_, _ = run("ip", "link", "set", af.VxlanName, "master", c.bridgeName)
		// bridge slave options
		ns := "off"
		if c.cfg.NeighSuppress {
			ns = "on"
		}
		_, _ = run("ip", "link", "set", af.VxlanName, "type", "bridge_slave", "hairpin", "on", "learning", "off", "neigh_suppress", ns)
		if _, err := run("ip", "link", "set", af.VxlanName, "up"); err != nil {
			return err
		}
		c.vxlanDevs[afName] = &VxlanDev{
			AF: afName,
			Name: af.VxlanName,
			VNI: af.VxlanVNI,
			MTU: af.VxlanMTU,
			BindAddr: af.BindAddr.Addr,
			DstPort: af.VxlanDstPort,
			SrcPortStart: af.VxlanSrcPortStart,
			SrcPortEnd: af.VxlanSrcPortEnd,
			BridgeName: c.bridgeName,
			Log: c.log,
		}
	}

	// tap-inject
	if _, err := run("ip", "tuntap", "add", "dev", tapName, "mode", "tap"); err != nil {
		// ignore if exists
	}
	_, _ = run("ip", "link", "set", tapName, "master", c.bridgeName)
	ns := "off"
	if c.cfg.NeighSuppress {
		ns = "on"
	}
	_, _ = run("ip", "link", "set", tapName, "type", "bridge_slave", "learning", "off", "neigh_suppress", ns)
	if _, err := run("ip", "link", "set", tapName, "up"); err != nil {
		return err
	}
	tap, err := OpenTap(tapName)
	if err != nil {
		return err
	}
	c.tap = tap

	if c.cfg.ClampMSSToMTU {
		if err := c.installMSSClampRules(); err != nil {
			c.log.Warn("install mss clamp failed", zap.Error(err))
		}
	}
	return nil
}

func (c *Client) installMSSClampRules() error {
	// Idempotent-ish: create/flush table each time.
	var sb strings.Builder
	sb.WriteString("table bridge vxlan_mss {\n")
	sb.WriteString("  chain forward {\n")
	sb.WriteString("    type filter hook forward priority filter; policy accept;\n")
	for _, vx := range c.vxlanDevs {
		sb.WriteString(fmt.Sprintf("    oifname %q ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu\n", vx.Name))
		sb.WriteString(fmt.Sprintf("    iifname %q ether type {ip, ip6} tcp flags syn tcp option maxseg size set rt mtu\n", vx.Name))
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	// Replace by deleting table first (ignore errors).
	_, _ = run("nft", "delete", "table", "bridge", "vxlan_mss")
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, string(out))
	}
	return nil
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if se := strings.TrimSpace(stderr.String()); se != "" {
			return out.String(), fmt.Errorf("%w: %s", err, se)
		}
		return out.String(), err
	}
	return out.String(), nil
}

