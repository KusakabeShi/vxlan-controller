package controller

import (
	"vxlan-controller/pkg/types"
)

// computeRouteMatrix uses Floyd-Warshall on the AdditionalCost-weighted LatencyMatrix.
func computeRouteMatrix(
	latencyMatrix map[types.ClientID]map[types.ClientID]*types.SelectedLatency,
	clients map[types.ClientID]*ClientInfo,
) map[types.ClientID]map[types.ClientID]*types.RouteEntry {
	// Collect all client IDs
	var nodes []types.ClientID
	nodeIdx := make(map[types.ClientID]int)
	for id := range clients {
		nodeIdx[id] = len(nodes)
		nodes = append(nodes, id)
	}
	n := len(nodes)
	if n == 0 {
		return make(map[types.ClientID]map[types.ClientID]*types.RouteEntry)
	}

	// Initialize cost matrix and next-hop matrix
	cost := make([][]float64, n)
	next := make([][]int, n)
	afMatrix := make([][]types.AFName, n)

	for i := 0; i < n; i++ {
		cost[i] = make([]float64, n)
		next[i] = make([]int, n)
		afMatrix[i] = make([]types.AFName, n)
		for j := 0; j < n; j++ {
			if i == j {
				cost[i][j] = 0
				next[i][j] = j
			} else {
				cost[i][j] = types.INF_LATENCY
				next[i][j] = -1
			}
		}
	}

	// Fill direct edges from LatencyMatrix with AdditionalCost weighting
	for src, dsts := range latencyMatrix {
		srcI, ok := nodeIdx[src]
		if !ok {
			continue
		}
		for dst, sl := range dsts {
			dstI, ok := nodeIdx[dst]
			if !ok {
				continue
			}
			if sl.Latency >= types.INF_LATENCY {
				continue
			}
			// cost = latency + AdditionalCost[dst]
			additionalCost := float64(0)
			if ci, ok := clients[dst]; ok {
				additionalCost = ci.AdditionalCost
			}
			c := sl.Latency + additionalCost
			if c < cost[srcI][dstI] {
				cost[srcI][dstI] = c
				next[srcI][dstI] = dstI
				afMatrix[srcI][dstI] = sl.AF
			}
		}
	}

	// Floyd-Warshall
	for k := 0; k < n; k++ {
		for i := 0; i < n; i++ {
			if cost[i][k] >= types.INF_LATENCY {
				continue
			}
			for j := 0; j < n; j++ {
				if cost[k][j] >= types.INF_LATENCY {
					continue
				}
				newCost := cost[i][k] + cost[k][j]
				if newCost < cost[i][j] {
					cost[i][j] = newCost
					next[i][j] = next[i][k]
					// AF for i->j is the AF of the first hop (i->next[i][k])
				}
			}
		}
	}

	// Build RouteMatrix from next-hop matrix
	result := make(map[types.ClientID]map[types.ClientID]*types.RouteEntry)
	for i := 0; i < n; i++ {
		src := nodes[i]
		result[src] = make(map[types.ClientID]*types.RouteEntry)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			dst := nodes[j]
			if next[i][j] < 0 {
				continue // unreachable
			}
			nextHopIdx := next[i][j]
			nextHop := nodes[nextHopIdx]
			// AF is for src->nextHop edge
			af := afMatrix[i][nextHopIdx]
			result[src][dst] = &types.RouteEntry{
				NextHop: nextHop,
				AF:      af,
			}
		}
	}

	return result
}
