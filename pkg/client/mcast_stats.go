package client

import (
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

// McastStats tracks per-source-MAC multicast packet counts.
type McastStats struct {
	mu   sync.Mutex
	macs map[string]*macCounters // key: src MAC string
}

type macCounters struct {
	txAccepted uint64
	txRejected map[string]uint64 // reason -> count
	rxAccepted uint64
	rxRejected map[string]uint64
}

func newMcastStats() *McastStats {
	return &McastStats{
		macs: make(map[string]*macCounters),
	}
}

func (ms *McastStats) get(mac string) *macCounters {
	mc, ok := ms.macs[mac]
	if !ok {
		mc = &macCounters{
			txRejected: make(map[string]uint64),
			rxRejected: make(map[string]uint64),
		}
		ms.macs[mac] = mc
	}
	return mc
}

// RecordTx records an outbound (tap → controller) mcast result.
func (ms *McastStats) RecordTx(frame []byte, accepted bool, reason string) {
	if len(frame) < 14 {
		return
	}
	srcMAC := net.HardwareAddr(frame[6:12]).String()

	ms.mu.Lock()
	mc := ms.get(srcMAC)
	if accepted {
		mc.txAccepted++
	} else {
		mc.txRejected[reason]++
	}
	ms.mu.Unlock()
}

// RecordRx records an inbound (controller → tap) mcast result.
func (ms *McastStats) RecordRx(frame []byte, accepted bool, reason string) {
	if len(frame) < 14 {
		return
	}
	srcMAC := net.HardwareAddr(frame[6:12]).String()

	ms.mu.Lock()
	mc := ms.get(srcMAC)
	if accepted {
		mc.rxAccepted++
	} else {
		mc.rxRejected[reason]++
	}
	ms.mu.Unlock()
}

// snapshotAndReset returns the current stats and resets all counters.
func (ms *McastStats) snapshotAndReset() []*pb.MACMcastStats {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var result []*pb.MACMcastStats
	for mac, mc := range ms.macs {
		hwAddr, err := net.ParseMAC(mac)
		if err != nil {
			continue
		}
		entry := &pb.MACMcastStats{
			Mac:        hwAddr,
			TxAccepted: mc.txAccepted,
			RxAccepted: mc.rxAccepted,
		}

		// Sum tx rejected across all reasons
		for _, count := range mc.txRejected {
			entry.TxRejected += count
		}
		// Sum rx rejected across all reasons
		for _, count := range mc.rxRejected {
			entry.RxRejected += count
		}

		// Per-reason breakdown
		for reason, count := range mc.txRejected {
			entry.RejectReasons = append(entry.RejectReasons, &pb.McastRejectReason{
				Direction: "tx",
				Reason:    reason,
				Count:     count,
			})
		}
		for reason, count := range mc.rxRejected {
			entry.RejectReasons = append(entry.RejectReasons, &pb.McastRejectReason{
				Direction: "rx",
				Reason:    reason,
				Count:     count,
			})
		}

		result = append(result, entry)
	}

	// Reset
	ms.macs = make(map[string]*macCounters)

	return result
}

// mcastStatsReportLoop periodically sends mcast stats to all controllers.
func (c *Client) mcastStatsReportLoop() {
	ticker := time.NewTicker(c.Config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := c.mcastStats.snapshotAndReset()
			if len(stats) == 0 {
				continue
			}

			report := &pb.McastStatsReport{
				MacStats: stats,
			}
			data, err := proto.Marshal(report)
			if err != nil {
				continue
			}

			msg := clientEncodeMessage(protocol.MsgMcastStatsReport, data)
			c.mu.Lock()
			for _, cc := range c.Controllers {
				select {
				case cc.SendQueue <- ClientQueueItem{Message: msg}:
				default:
				}
			}
			c.mu.Unlock()

			vlog.Verbosef("[Client] mcast stats report sent (%d MACs)", len(stats))
		case <-c.ctx.Done():
			return
		}
	}
}
