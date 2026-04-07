package controller

import (
	"net"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

// ClientMcastStats stores the latest mcast stats reported by a client.
type ClientMcastStats struct {
	MACs map[string]*MACMcastStats // key: src MAC string
}

// MACMcastStats is per-MAC stats from a client report.
type MACMcastStats struct {
	TxAccepted    uint64
	TxRejected    uint64
	RxAccepted    uint64
	RxRejected    uint64
	RejectReasons []RejectReason
}

// RejectReason is a single reason + count with optional detail breakdown.
type RejectReason struct {
	Direction string // "tx" or "rx"
	Reason    string
	Count     uint64
	Details   []RejectDetail
}

// RejectDetail is a single deduped detail entry within a reason.
type RejectDetail struct {
	Detail string
	Count  uint64
}

func (c *Controller) handleMcastStatsReport(cc *ClientConn, payload []byte) {
	var report pb.McastStatsReport
	if err := proto.Unmarshal(payload, &report); err != nil {
		vlog.Errorf("[Controller] unmarshal McastStatsReport error: %v", err)
		return
	}

	stats := &ClientMcastStats{
		MACs: make(map[string]*MACMcastStats, len(report.MacStats)),
	}
	for _, ms := range report.MacStats {
		mac := net.HardwareAddr(ms.Mac).String()
		entry := &MACMcastStats{
			TxAccepted: ms.TxAccepted,
			TxRejected: ms.TxRejected,
			RxAccepted: ms.RxAccepted,
			RxRejected: ms.RxRejected,
		}
		for _, rr := range ms.RejectReasons {
			r := RejectReason{
				Direction: rr.Direction,
				Reason:    rr.Reason,
				Count:     rr.Count,
			}
			for _, d := range rr.Details {
				r.Details = append(r.Details, RejectDetail{
					Detail: d.Detail,
					Count:  d.Count,
				})
			}
			entry.RejectReasons = append(entry.RejectReasons, r)
		}
		stats.MACs[mac] = entry
	}

	c.mu.Lock()
	c.clientMcastStats[cc.ClientID] = stats
	c.mu.Unlock()

	vlog.Verbosef("[Controller] mcast stats from %s: %d MACs", cc.ClientID.Hex()[:8], len(stats.MACs))
}
