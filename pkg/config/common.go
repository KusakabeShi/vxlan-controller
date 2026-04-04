package config

import (
	"fmt"
	"net/netip"
	"time"

	"vxlan-controller/pkg/types"
)

type Key32B64 struct {
	Raw string `yaml:"-"`
	Key [32]byte
}

func (k *Key32B64) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	key, err := types.ParseKey32Base64(s)
	if err != nil {
		return err
	}
	k.Raw = s
	k.Key = key
	return nil
}

type Addr struct {
	Raw  string `yaml:"-"`
	Addr netip.Addr
}

func (a *Addr) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", s, err)
	}
	a.Raw = s
	a.Addr = ip
	return nil
}

type AddrPort struct {
	Raw  string `yaml:"-"`
	Addr netip.AddrPort
}

func (ap *AddrPort) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	p, err := netip.ParseAddrPort(s)
	if err != nil {
		return fmt.Errorf("parse addrport %q: %w", s, err)
	}
	ap.Raw = s
	ap.Addr = p
	return nil
}

type Duration struct {
	Raw string `yaml:"-"`
	D   time.Duration
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		dd, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", s, err)
		}
		d.Raw = s
		d.D = dd
		return nil
	}
	var sec int
	if err := unmarshal(&sec); err == nil {
		d.D = time.Duration(sec) * time.Second
		d.Raw = fmt.Sprintf("%ds", sec)
		return nil
	}
	return fmt.Errorf("invalid duration (expect string like 10s or int seconds)")
}

