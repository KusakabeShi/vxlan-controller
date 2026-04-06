package types

import (
	"encoding/hex"
	"net"
	"net/netip"
	"time"

	"vxlan-controller/pkg/filter"
)

// ClientID is an X25519 public key, 32 bytes.
type ClientID [32]byte

func (id ClientID) Hex() string {
	return hex.EncodeToString(id[:])
}

func ClientIDFromHex(s string) (ClientID, error) {
	var id ClientID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	copy(id[:], b)
	return id, nil
}

// ControllerID is the same as ClientID (X25519 public key).
type ControllerID = ClientID

// AFName represents an address family, e.g. "v4", "v6", "asia_v4".
type AFName string

// Endpoint represents a connection endpoint for a given AF.
type Endpoint struct {
	IP           netip.Addr
	ProbePort    uint16
	VxlanDstPort uint16
}

// PerClientConfig is the Controller's per-client configuration.
type PerClientConfig struct {
	ClientID       ClientID
	ClientName     string
	AdditionalCost float64 // default 20
	Filters        *filter.FilterConfig
}

// ClientInfo is maintained by the Controller for each connected Client.
type ClientInfo struct {
	ClientID       ClientID
	ClientName     string
	Endpoints      map[AFName]*Endpoint
	LastSeen       time.Time
	Routes         []Type2Route
	AdditionalCost float64
}

// Type2Route mimics EVPN Type-2 route.
type Type2Route struct {
	MAC net.HardwareAddr
	IP  netip.Addr
}

// LatencyEntry stores per-AF probe results.
type LatencyEntry struct {
	LatencyMean float64
	LatencyStd  float64
	PacketLoss  float64
	Priority    int
}

// SelectedLatency is the chosen latency for LatencyMatrix.
type SelectedLatency struct {
	Latency float64
	AF      AFName
}

// RouteEntry is a single cell in RouteMatrix.
type RouteEntry struct {
	NextHop ClientID
	AF      AFName
}

// RouteTableEntry stores MAC/IP ownership.
type RouteTableEntry struct {
	MAC    net.HardwareAddr
	IP     netip.Addr
	Owners map[ClientID]time.Time // client_id -> ExpireTime
}

// INF_LATENCY represents unreachable.
const INF_LATENCY = 1e18
