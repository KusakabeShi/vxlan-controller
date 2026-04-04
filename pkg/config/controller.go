package config

import (
	"fmt"
	"time"

	"vxlan-controller/pkg/types"
)

type ControllerConfig struct {
	PrivateKey Key32B64 `yaml:"private_key"`

	AFSettings map[types.AFName]*ControllerAFConfig `yaml:"address_families"`

	ClientOfflineTimeout       Duration `yaml:"client_offline_timeout"`
	SyncNewClientDebounce      Duration `yaml:"sync_new_client_debounce"`
	SyncNewClientDebounceMax   Duration `yaml:"sync_new_client_debounce_max"`
	TopologyUpdateDebounce     Duration `yaml:"topology_update_debounce"`
	TopologyUpdateDebounceMax  Duration `yaml:"topology_update_debounce_max"`
	Probing                    ProbingConfig `yaml:"probing"`
	AllowedClients             []PerClientConfig `yaml:"allowed_clients"`
}

type ControllerAFConfig struct {
	Name              types.AFName `yaml:"name"`
	Enable            bool         `yaml:"enable"`
	BindAddr          Addr         `yaml:"bind_addr"`
	CommunicationPort uint16       `yaml:"communication_port"`

	VxlanVNI           uint32 `yaml:"vxlan_vni"`
	VxlanDstPort       uint16 `yaml:"vxlan_dstport"`
	VxlanSrcPortStart  uint16 `yaml:"vxlan_srcport_start"`
	VxlanSrcPortEnd    uint16 `yaml:"vxlan_srcport_end"`
}

type ProbingConfig struct {
	ProbeIntervalS    int `yaml:"probe_interval_s"`
	ProbeTimes        int `yaml:"probe_times"`
	InProbeIntervalMs int `yaml:"in_probe_interval_ms"`
	ProbeTimeoutMs    int `yaml:"probe_timeout_ms"`
}

type PerClientConfig struct {
	ClientID       Key32B64 `yaml:"client_id"`
	ClientName     string   `yaml:"client_name"`
	AdditionalCost float64  `yaml:"additional_cost"`
}

func (c *ControllerConfig) ApplyDefaults() {
	if c.ClientOfflineTimeout.D == 0 {
		c.ClientOfflineTimeout.D = 300 * time.Second
	}
	if c.SyncNewClientDebounce.D == 0 {
		c.SyncNewClientDebounce.D = 2 * time.Second
	}
	if c.SyncNewClientDebounceMax.D == 0 {
		c.SyncNewClientDebounceMax.D = 10 * time.Second
	}
	if c.TopologyUpdateDebounce.D == 0 {
		c.TopologyUpdateDebounce.D = 1 * time.Second
	}
	if c.TopologyUpdateDebounceMax.D == 0 {
		c.TopologyUpdateDebounceMax.D = 5 * time.Second
	}
	if c.Probing.ProbeIntervalS == 0 {
		c.Probing.ProbeIntervalS = 60
	}
	if c.Probing.ProbeTimes == 0 {
		c.Probing.ProbeTimes = 5
	}
	if c.Probing.InProbeIntervalMs == 0 {
		c.Probing.InProbeIntervalMs = 200
	}
	if c.Probing.ProbeTimeoutMs == 0 {
		c.Probing.ProbeTimeoutMs = 1000
	}
	for name, af := range c.AFSettings {
		if af == nil {
			continue
		}
		if af.Name == "" {
			af.Name = name
		}
		if af.VxlanSrcPortStart == 0 {
			af.VxlanSrcPortStart = af.VxlanDstPort
		}
		if af.VxlanSrcPortEnd == 0 {
			af.VxlanSrcPortEnd = af.VxlanDstPort
		}
	}
	for i := range c.AllowedClients {
		if c.AllowedClients[i].AdditionalCost == 0 {
			c.AllowedClients[i].AdditionalCost = 20
		}
	}
}

func (c *ControllerConfig) Validate() error {
	if c.PrivateKey.Key == ([32]byte{}) {
		return fmt.Errorf("private_key is required")
	}
	if len(c.AFSettings) == 0 {
		return fmt.Errorf("address_families is required")
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
		if af.CommunicationPort == 0 {
			return fmt.Errorf("af %q: communication_port is required", name)
		}
		if af.VxlanVNI == 0 || af.VxlanDstPort == 0 {
			return fmt.Errorf("af %q: vxlan_vni/vxlan_dstport is required", name)
		}
		if af.VxlanSrcPortStart == 0 || af.VxlanSrcPortEnd == 0 {
			return fmt.Errorf("af %q: vxlan_srcport_start/end required (or leave empty to default)", name)
		}
	}
	if c.ClientOfflineTimeout.D <= 0 {
		return fmt.Errorf("client_offline_timeout must be > 0")
	}
	if c.SyncNewClientDebounce.D <= 0 || c.SyncNewClientDebounceMax.D <= 0 || c.SyncNewClientDebounceMax.D < c.SyncNewClientDebounce.D {
		return fmt.Errorf("invalid sync_new_client_debounce config")
	}
	if c.TopologyUpdateDebounce.D <= 0 || c.TopologyUpdateDebounceMax.D <= 0 || c.TopologyUpdateDebounceMax.D < c.TopologyUpdateDebounce.D {
		return fmt.Errorf("invalid topology_update_debounce config")
	}
	if c.Probing.ProbeTimes <= 0 || c.Probing.InProbeIntervalMs <= 0 || c.Probing.ProbeTimeoutMs <= 0 || c.Probing.ProbeIntervalS <= 0 {
		return fmt.Errorf("invalid probing config")
	}
	totalMs := c.Probing.ProbeTimes*c.Probing.InProbeIntervalMs + c.Probing.ProbeTimeoutMs
	if totalMs >= (c.Probing.ProbeIntervalS-1)*1000 {
		return fmt.Errorf("probing config violates constraint: probe_times*in_probe_interval_ms+probe_timeout_ms < (probe_interval_s-1)*1000")
	}
	if c.SyncNewClientDebounce.D <= time.Duration(totalMs)*time.Millisecond {
		return fmt.Errorf("sync_new_client_debounce must be > probe_times*in_probe_interval_ms + probe_timeout_ms")
	}
	if len(c.AllowedClients) == 0 {
		return fmt.Errorf("allowed_clients is required")
	}
	return nil
}

