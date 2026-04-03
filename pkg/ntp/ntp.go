package ntp

import (
	"log"
	"sync"
	"time"

	"github.com/beevik/ntp"
)

// TimeSync manages NTP time offset correction.
type TimeSync struct {
	mu      sync.RWMutex
	offset  time.Duration
	servers []string
}

func New(servers []string) *TimeSync {
	return &TimeSync{servers: servers}
}

// Sync queries NTP servers and updates the offset.
func (ts *TimeSync) Sync() error {
	for _, server := range ts.servers {
		resp, err := ntp.Query(server)
		if err != nil {
			continue
		}
		if err := resp.Validate(); err != nil {
			continue
		}

		ts.mu.Lock()
		ts.offset = resp.ClockOffset
		ts.mu.Unlock()

		log.Printf("[NTP] synced with %s, offset=%v", server, resp.ClockOffset)
		return nil
	}
	return nil // non-fatal: keep running with current offset
}

// Now returns the corrected current time.
func (ts *TimeSync) Now() time.Time {
	ts.mu.RLock()
	offset := ts.offset
	ts.mu.RUnlock()
	return time.Now().Add(offset)
}

// Offset returns the current NTP offset.
func (ts *TimeSync) Offset() time.Duration {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.offset
}

// RunLoop periodically syncs NTP. Call in a goroutine.
func (ts *TimeSync) RunLoop(interval time.Duration, stop <-chan struct{}) {
	// Initial sync
	ts.Sync()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ts.Sync()
		case <-stop:
			return
		}
	}
}
