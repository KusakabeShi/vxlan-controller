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

type ControllerConfigFile struct {
	PrivateKey             string                              `yaml:"private_key"`
	AFSettings             map[string]*ControllerAFConfigFile  `yaml:"address_families"`
	ClientOfflineTimeout   int                                 `yaml:"client_offline_timeout"`
	SyncNewClientDebounce  int                                 `yaml:"sync_new_client_debounce"`
	SyncNewClientDebounceMax int                               `yaml:"sync_new_client_debounce_max"`
	TopologyUpdateDebounce int                                 `yaml:"topology_update_debounce"`
	TopologyUpdateDebounceMax int                              `yaml:"topology_update_debounce_max"`
	Probing                ProbingConfigFile                   `yaml:"probing"`
	AllowedClients         []PerClientConfigFile               `yaml:"allowed_clients"`
}

type ControllerAFConfigFile struct {
	Enable            bool   `yaml:"enable"`
	BindAddr          string `yaml:"bind_addr"`
	CommunicationPort uint16 `yaml:"communication_port"`
	VxlanVNI          uint32 `yaml:"vxlan_vni"`
	VxlanDstPort      uint16 `yaml:"vxlan_dst_port"`
	VxlanSrcPortStart uint16 `yaml:"vxlan_src_port_start"`
	VxlanSrcPortEnd   uint16 `yaml:"vxlan_src_port_end"`
}

type ProbingConfigFile struct {
	ProbeIntervalS    int `yaml:"probe_interval_s"`
	ProbeTimes        int `yaml:"probe_times"`
	InProbeIntervalMs int `yaml:"in_probe_interval_ms"`
	ProbeTimeoutMs    int `yaml:"probe_timeout_ms"`
}

type PerClientConfigFile struct {
	ClientID       string  `yaml:"client_id"`
	ClientName     string  `yaml:"client_name"`
	AdditionalCost float64 `yaml:"additional_cost"`
}

// ControllerConfig is the parsed controller configuration.
type ControllerConfig struct {
	PrivateKey                [32]byte
	AFSettings                map[types.AFName]*ControllerAFConfig
	ClientOfflineTimeout      time.Duration
	SyncNewClientDebounce     time.Duration
	SyncNewClientDebounceMax  time.Duration
	TopologyUpdateDebounce    time.Duration
	TopologyUpdateDebounceMax time.Duration
	Probing                   ProbingConfig
	AllowedClients            []types.PerClientConfig
}

type ControllerAFConfig struct {
	Name              types.AFName
	Enable            bool
	BindAddr          netip.Addr
	CommunicationPort uint16
	VxlanVNI          uint32
	VxlanDstPort      uint16
	VxlanSrcPortStart uint16
	VxlanSrcPortEnd   uint16
}

type ProbingConfig struct {
	ProbeIntervalS    int
	ProbeTimes        int
	InProbeIntervalMs int
	ProbeTimeoutMs    int
}

func LoadControllerConfig(path string) (*ControllerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Start from defaults, then overlay user config
	raw := DefaultControllerConfig
	raw.AFSettings = nil      // clear so user must specify
	raw.AllowedClients = nil  // clear so user must specify
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	cfg := &ControllerConfig{
		ClientOfflineTimeout:      time.Duration(raw.ClientOfflineTimeout) * time.Second,
		SyncNewClientDebounce:     time.Duration(raw.SyncNewClientDebounce) * time.Second,
		SyncNewClientDebounceMax:  time.Duration(raw.SyncNewClientDebounceMax) * time.Second,
		TopologyUpdateDebounce:    time.Duration(raw.TopologyUpdateDebounce) * time.Second,
		TopologyUpdateDebounceMax: time.Duration(raw.TopologyUpdateDebounceMax) * time.Second,
		Probing: ProbingConfig{
			ProbeIntervalS:    raw.Probing.ProbeIntervalS,
			ProbeTimes:        raw.Probing.ProbeTimes,
			InProbeIntervalMs: raw.Probing.InProbeIntervalMs,
			ProbeTimeoutMs:    raw.Probing.ProbeTimeoutMs,
		},
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

	// Parse AF settings
	cfg.AFSettings = make(map[types.AFName]*ControllerAFConfig)
	for name, afRaw := range raw.AFSettings {
		afName := types.AFName(name)
		af := &ControllerAFConfig{
			Name:              afName,
			Enable:            afRaw.Enable,
			CommunicationPort: afRaw.CommunicationPort,
			VxlanVNI:          afRaw.VxlanVNI,
			VxlanDstPort:      afRaw.VxlanDstPort,
			VxlanSrcPortStart: afRaw.VxlanSrcPortStart,
			VxlanSrcPortEnd:   afRaw.VxlanSrcPortEnd,
		}

		af.BindAddr, err = netip.ParseAddr(afRaw.BindAddr)
		if err != nil {
			return nil, fmt.Errorf("af %s: invalid bind_addr: %w", name, err)
		}

		cfg.AFSettings[afName] = af
	}

	// Parse allowed clients
	for _, clientRaw := range raw.AllowedClients {
		pc := types.PerClientConfig{
			ClientName:     clientRaw.ClientName,
			AdditionalCost: clientRaw.AdditionalCost,
		}
		if pc.AdditionalCost == 0 {
			pc.AdditionalCost = 20
		}

		pubBytes, err := base64.StdEncoding.DecodeString(clientRaw.ClientID)
		if err != nil {
			return nil, fmt.Errorf("client %s: invalid client_id base64: %w", clientRaw.ClientName, err)
		}
		if len(pubBytes) != 32 {
			return nil, fmt.Errorf("client %s: client_id must be 32 bytes", clientRaw.ClientName)
		}
		copy(pc.ClientID[:], pubBytes)

		cfg.AllowedClients = append(cfg.AllowedClients, pc)
	}

	return cfg, nil
}
