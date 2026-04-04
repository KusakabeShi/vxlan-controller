package config

import (
	"fmt"
	"time"

	"vxlan-controller/pkg/types"
)

type ClientConfig struct {
	PrivateKey       Key32B64 `yaml:"private_key"`
	BridgeName       string   `yaml:"bridge_name"`
	ClampMSSToMTU    bool     `yaml:"clamp_mss_to_mtu"`
	NeighSuppress    bool     `yaml:"neigh_suppress"`
	BroadcastPPSLimit int     `yaml:"broadcast_pps_limit"`

	AFSettings map[types.AFName]*ClientAFConfig `yaml:"address_families"`

	FDBDebounceMs    int      `yaml:"fdb_debounce_ms"`
	FDBDebounceMaxMs int      `yaml:"fdb_debounce_max_ms"`
	InitTimeout      Duration `yaml:"init_timeout"`

	NTPServers        []string `yaml:"ntp_servers"`
	NTPResyncInterval Duration `yaml:"ntp_resync_interval"`

	APIUnixSocket string `yaml:"api_unix_socket"`
}

type ClientAFConfig struct {
	Name              types.AFName `yaml:"name"`
	Enable            bool         `yaml:"enable"`
	BindAddr          Addr         `yaml:"bind_addr"`
	ProbePort         uint16       `yaml:"probe_port"`
	CommunicationPort uint16       `yaml:"communication_port"`

	VxlanName          string `yaml:"vxlan_name"`
	VxlanVNI           uint32 `yaml:"vxlan_vni"`
	VxlanMTU           int    `yaml:"vxlan_mtu"`
	VxlanDstPort       uint16 `yaml:"vxlan_dstport"`
	VxlanSrcPortStart  uint16 `yaml:"vxlan_srcport_start"`
	VxlanSrcPortEnd    uint16 `yaml:"vxlan_srcport_end"`

	Priority    int32                `yaml:"priority"`
	Controllers []ControllerEndpoint `yaml:"controllers"`
}

type ControllerEndpoint struct {
	PubKey Key32B64 `yaml:"pubkey"`
	Addr   AddrPort `yaml:"addr"`
}

func (c *ClientConfig) ApplyDefaults() {
	if c.BridgeName == "" {
		c.BridgeName = "br-vxlan"
	}
	if c.FDBDebounceMs == 0 {
		c.FDBDebounceMs = 500
	}
	if c.FDBDebounceMaxMs == 0 {
		c.FDBDebounceMaxMs = 3000
	}
	if c.InitTimeout.D == 0 {
		c.InitTimeout.D = 10 * time.Second
	}
	if c.NTPResyncInterval.D == 0 {
		c.NTPResyncInterval.D = 23 * time.Hour
	}
	if c.BroadcastPPSLimit == 0 {
		c.BroadcastPPSLimit = 2000
	}

	for name, af := range c.AFSettings {
		if af == nil {
			continue
		}
		if af.Name == "" {
			af.Name = name
		}
		if af.VxlanName == "" {
			af.VxlanName = fmt.Sprintf("vxlan-%s", af.Name)
		}
		if af.VxlanMTU == 0 {
			af.VxlanMTU = 1450
		}
		if af.VxlanSrcPortStart == 0 {
			af.VxlanSrcPortStart = af.VxlanDstPort
		}
		if af.VxlanSrcPortEnd == 0 {
			af.VxlanSrcPortEnd = af.VxlanDstPort
		}
	}
}

func (c *ClientConfig) Validate() error {
	if c.PrivateKey.Key == ([32]byte{}) {
		return fmt.Errorf("private_key is required")
	}
	if c.BridgeName == "" {
		return fmt.Errorf("bridge_name is required")
	}
	if len(c.AFSettings) == 0 {
		return fmt.Errorf("address_families is required")
	}
	if c.FDBDebounceMs <= 0 || c.FDBDebounceMaxMs <= 0 || c.FDBDebounceMaxMs < c.FDBDebounceMs {
		return fmt.Errorf("invalid fdb debounce config")
	}
	if c.InitTimeout.D <= 0 {
		return fmt.Errorf("init_timeout must be > 0")
	}
	if c.BroadcastPPSLimit < 0 {
		return fmt.Errorf("broadcast_pps_limit must be >= 0")
	}
	for name, af := range c.AFSettings {
		if af == nil || !af.Enable {
			continue
		}
		if af.Name == "" {
			af.Name = name
		}
		if !af.BindAddr.Addr.IsValid() {
			return fmt.Errorf("af %q: bind_addr is required", name)
		}
		if af.ProbePort == 0 {
			return fmt.Errorf("af %q: probe_port is required", name)
		}
		if af.CommunicationPort == 0 {
			return fmt.Errorf("af %q: communication_port is required", name)
		}
		if af.VxlanVNI == 0 {
			return fmt.Errorf("af %q: vxlan_vni is required", name)
		}
		if af.VxlanDstPort == 0 {
			return fmt.Errorf("af %q: vxlan_dstport is required", name)
		}
		if af.VxlanSrcPortStart == 0 || af.VxlanSrcPortEnd == 0 {
			return fmt.Errorf("af %q: vxlan_srcport_start/end required (or leave empty to default)", name)
		}
		if len(af.Controllers) == 0 {
			return fmt.Errorf("af %q: controllers is required", name)
		}
	}
	return nil
}
