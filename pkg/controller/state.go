package controller

import (
	"net/netip"
	"time"

	"vxlan-controller/pkg/types"
)

type Endpoint struct {
	IP                netip.Addr
	ProbePort         uint16
	CommunicationPort uint16
	VxlanDstPort      uint16
	Priority          int32
}

type ClientInfo struct {
	ClientID       types.ClientID
	Endpoints      map[types.AFName]*Endpoint
	LastSeen       time.Time
	AdditionalCost float64
}

type SelectedLatency struct {
	LatencyMs float64
	AF        types.AFName
}

type RouteEntry struct {
	NextHop types.ClientID
	AF      types.AFName
}

type RouteTableEntry struct {
	MAC    [6]byte
	IP     netip.Addr // invalid means absent
	Owners map[types.ClientID]time.Time
}

type ControllerState struct {
	Clients           map[types.ClientID]*ClientInfo
	LatencyMatrix     map[types.ClientID]map[types.ClientID]*SelectedLatency
	RouteMatrix       map[types.ClientID]map[types.ClientID]*RouteEntry
	RouteTable        map[string]*RouteTableEntry
	LastClientChange  time.Time
}

