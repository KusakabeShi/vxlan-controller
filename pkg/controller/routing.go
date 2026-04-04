package controller

import (
	"math"
	"sort"

	"vxlan-controller/pkg/types"
)

func ComputeRouteMatrix(
	clients map[types.ClientID]*ClientInfo,
	latency map[types.ClientID]map[types.ClientID]*SelectedLatency,
) map[types.ClientID]map[types.ClientID]*RouteEntry {
	ids := make([]types.ClientID, 0, len(clients))
	addCost := make(map[types.ClientID]float64, len(clients))
	for id, info := range clients {
		ids = append(ids, id)
		addCost[id] = info.AdditionalCost
	}
	sort.Slice(ids, func(i, j int) bool { return types.CompareClientID(ids[i], ids[j]) < 0 })
	n := len(ids)

	const inf = math.MaxFloat64 / 4
	dist := make([][]float64, n)
	next := make([][]int, n)
	for i := 0; i < n; i++ {
		dist[i] = make([]float64, n)
		next[i] = make([]int, n)
		for j := 0; j < n; j++ {
			next[i][j] = -1
			if i == j {
				dist[i][j] = 0
				continue
			}
			li := latency[ids[i]][ids[j]]
			if li == nil || li.LatencyMs <= 0 || math.IsInf(li.LatencyMs, 1) {
				dist[i][j] = inf
				continue
			}
			cost := li.LatencyMs + addCost[ids[j]]
			dist[i][j] = cost
			next[i][j] = j
		}
	}

	for k := 0; k < n; k++ {
		for i := 0; i < n; i++ {
			if dist[i][k] >= inf {
				continue
			}
			for j := 0; j < n; j++ {
				if dist[k][j] >= inf {
					continue
				}
				nd := dist[i][k] + dist[k][j]
				if nd < dist[i][j] {
					dist[i][j] = nd
					next[i][j] = next[i][k]
				}
			}
		}
	}

	out := make(map[types.ClientID]map[types.ClientID]*RouteEntry, n)
	for i := 0; i < n; i++ {
		src := ids[i]
		out[src] = make(map[types.ClientID]*RouteEntry, n)
		for j := 0; j < n; j++ {
			dst := ids[j]
			if i == j {
				continue
			}
			nh := next[i][j]
			if nh < 0 || dist[i][j] >= inf {
				out[src][dst] = nil
				continue
			}
			nexthop := ids[nh]
			li := latency[src][nexthop]
			if li == nil {
				out[src][dst] = nil
				continue
			}
			out[src][dst] = &RouteEntry{NextHop: nexthop, AF: li.AF}
		}
	}
	return out
}

