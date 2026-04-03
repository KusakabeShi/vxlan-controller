package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"time"

	"vxlan-controller/pkg/types"

	"gopkg.in/yaml.v3"
)

type ClientConfigFile struct {
	PrivateKey        string                          `yaml:"private_key"`
	BridgeName        string                          `yaml:"bridge_name"`
	ClampMSSToMTU     bool                            `yaml:"clamp_mss_to_mtu"`
	NeighSuppress     bool                            `yaml:"neigh_suppress"`
	AFSettings        map[string]*ClientAFConfigFile   `yaml:"address_families"`
	FDBDebounceMs     int                             `yaml:"fdb_debounce_ms"`
	FDBDebounceMaxMs  int                             `yaml:"fdb_debounce_max_ms"`
	InitTimeout       int                             `yaml:"init_timeout"`
	NTPServers        []string                        `yaml:"ntp_servers"`
}

type ClientAFConfigFile struct {
	Enable            bool                            `yaml:"enable"`
	BindAddr          string                          `yaml:"bind_addr"`
	ProbePort         uint16                          `yaml:"probe_port"`
	CommunicationPort uint16                          `yaml:"communication_port"`
	VxlanName         string                          `yaml:"vxlan_name"`
	VxlanVNI          uint32                          `yaml:"vxlan_vni"`
	VxlanMTU          int                             `yaml:"vxlan_mtu"`
	VxlanDstPort      uint16                          `yaml:"vxlan_dst_port"`
	Priority          int                             `yaml:"priority"`
	Controllers       []ControllerEndpointFile        `yaml:"controllers"`
}

type ControllerEndpointFile struct {
	PubKey string `yaml:"pubkey"`
	Addr   string `yaml:"addr"`
}

// ClientConfig is the parsed client configuration.
type ClientConfig struct {
	PrivateKey       [32]byte
	BridgeName       string
	ClampMSSToMTU    bool
	NeighSuppress    bool
	AFSettings       map[types.AFName]*ClientAFConfig
	FDBDebounceMs    int
	FDBDebounceMaxMs int
	InitTimeout      time.Duration
	NTPServers       []string
}

type ClientAFConfig struct {
	Name              types.AFName
	Enable            bool
	BindAddr          netip.Addr
	ProbePort         uint16
	CommunicationPort uint16
	VxlanName         string
	VxlanVNI          uint32
	VxlanMTU          int
	VxlanDstPort      uint16
	Priority          int
	Controllers       []ControllerEndpoint
}

type ControllerEndpoint struct {
	PubKey [32]byte
	Addr   netip.AddrPort
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var raw ClientConfigFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	cfg := &ClientConfig{
		BridgeName:    raw.BridgeName,
		ClampMSSToMTU: raw.ClampMSSToMTU,
		NeighSuppress: raw.NeighSuppress,
		NTPServers:    raw.NTPServers,
	}

	// Parse private key
	keyBytes, err := base64.StdEncoding.DecodeString(raw.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private_key base64: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("private_key must be 32 bytes, got %d", len(keyBytes))
	}
	copy(cfg.PrivateKey[:], keyBytes)

	// Defaults
	cfg.FDBDebounceMs = raw.FDBDebounceMs
	if cfg.FDBDebounceMs == 0 {
		cfg.FDBDebounceMs = 500
	}
	cfg.FDBDebounceMaxMs = raw.FDBDebounceMaxMs
	if cfg.FDBDebounceMaxMs == 0 {
		cfg.FDBDebounceMaxMs = 3000
	}
	if raw.InitTimeout == 0 {
		cfg.InitTimeout = 10 * time.Second
	} else {
		cfg.InitTimeout = time.Duration(raw.InitTimeout) * time.Second
	}

	// Parse AF settings
	cfg.AFSettings = make(map[types.AFName]*ClientAFConfig)
	for name, afRaw := range raw.AFSettings {
		afName := types.AFName(name)
		af := &ClientAFConfig{
			Name:              afName,
			Enable:            afRaw.Enable,
			ProbePort:         afRaw.ProbePort,
			CommunicationPort: afRaw.CommunicationPort,
			VxlanName:         afRaw.VxlanName,
			VxlanVNI:          afRaw.VxlanVNI,
			VxlanMTU:          afRaw.VxlanMTU,
			VxlanDstPort:      afRaw.VxlanDstPort,
			Priority:          afRaw.Priority,
		}

		af.BindAddr, err = netip.ParseAddr(afRaw.BindAddr)
		if err != nil {
			return nil, fmt.Errorf("af %s: invalid bind_addr: %w", name, err)
		}

		for _, ctrl := range afRaw.Controllers {
			ce := ControllerEndpoint{}
			pubBytes, err := base64.StdEncoding.DecodeString(ctrl.PubKey)
			if err != nil {
				return nil, fmt.Errorf("af %s: invalid controller pubkey: %w", name, err)
			}
			if len(pubBytes) != 32 {
				return nil, fmt.Errorf("af %s: controller pubkey must be 32 bytes", name)
			}
			copy(ce.PubKey[:], pubBytes)

			ce.Addr, err = netip.ParseAddrPort(ctrl.Addr)
			if err != nil {
				return nil, fmt.Errorf("af %s: invalid controller addr: %w", name, err)
			}

			af.Controllers = append(af.Controllers, ce)
		}

		cfg.AFSettings[afName] = af
	}

	return cfg, nil
}
