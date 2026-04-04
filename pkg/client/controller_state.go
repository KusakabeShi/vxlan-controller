package client

import (
	"fmt"
	"net/netip"

	pb "vxlan-controller/proto"
	"vxlan-controller/pkg/types"
)

type ControllerView struct {
	Raw *pb.ControllerState

	ClientsByID map[types.ClientID]*pb.ClientInfo
	Latency     map[types.ClientID]map[types.ClientID]*pb.SelectedLatency
	Route       map[types.ClientID]map[types.ClientID]*pb.RouteEntry
	RouteTable  []*pb.RouteTableEntry
}

func BuildControllerView(st *pb.ControllerState) (*ControllerView, error) {
	if st == nil {
		return nil, nil
	}
	v := &ControllerView{
		Raw: st,
		ClientsByID: make(map[types.ClientID]*pb.ClientInfo),
		Latency: make(map[types.ClientID]map[types.ClientID]*pb.SelectedLatency),
		Route: make(map[types.ClientID]map[types.ClientID]*pb.RouteEntry),
		RouteTable: st.GetRouteTable(),
	}
	for _, ci := range st.GetClients() {
		if ci == nil || len(ci.ClientId) != 32 {
			continue
		}
		var id types.ClientID
		copy(id[:], ci.ClientId)
		v.ClientsByID[id] = ci
	}
	for _, row := range st.GetLatencyMatrix() {
		if row == nil || len(row.SrcClientId) != 32 {
			continue
		}
		var src types.ClientID
		copy(src[:], row.SrcClientId)
		v.Latency[src] = make(map[types.ClientID]*pb.SelectedLatency)
		for _, e := range row.GetEntries() {
			if e == nil || len(e.DstClientId) != 32 {
				continue
			}
			var dst types.ClientID
			copy(dst[:], e.DstClientId)
			v.Latency[src][dst] = e
		}
	}
	for _, row := range st.GetRouteMatrix() {
		if row == nil || len(row.SrcClientId) != 32 {
			continue
		}
		var src types.ClientID
		copy(src[:], row.SrcClientId)
		v.Route[src] = make(map[types.ClientID]*pb.RouteEntry)
		for _, e := range row.GetEntries() {
			if e == nil || len(e.DstClientId) != 32 {
				continue
			}
			var dst types.ClientID
			copy(dst[:], e.DstClientId)
			v.Route[src][dst] = e
		}
	}
	return v, nil
}

func (v *ControllerView) EndpointIP(clientID types.ClientID, af types.AFName) (netip.Addr, uint16, error) {
	ci := v.ClientsByID[clientID]
	if ci == nil {
		return netip.Addr{}, 0, fmt.Errorf("unknown client")
	}
	for _, ep := range ci.GetEndpoints() {
		if ep == nil {
			continue
		}
		if types.AFName(ep.GetAfName()) != af {
			continue
		}
		ip, err := types.BytesToNetIP(ep.GetIp())
		if err != nil {
			return netip.Addr{}, 0, err
		}
		return ip, uint16(ep.GetProbePort()), nil
	}
	return netip.Addr{}, 0, fmt.Errorf("missing endpoint")
}

