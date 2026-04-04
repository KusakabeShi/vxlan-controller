package ntp

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/beevik/ntp"
	"go.uber.org/zap"
)

type Offset struct {
	v atomic.Int64 // nanoseconds
}

func (o *Offset) Load() time.Duration { return time.Duration(o.v.Load()) }
func (o *Offset) Store(d time.Duration) { o.v.Store(int64(d)) }

func SyncOnce(ctx context.Context, logger *zap.Logger, servers []string, timeout time.Duration) (time.Duration, error) {
	if len(servers) == 0 {
		return 0, nil
	}
	var lastErr error
	for _, s := range servers {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		rsp, err := ntp.QueryWithOptions(s, ntp.QueryOptions{Timeout: timeout})
		if err != nil {
			lastErr = err
			if logger != nil {
				logger.Warn("ntp query failed", zap.String("server", s), zap.Error(err))
			}
			continue
		}
		return rsp.ClockOffset, nil
	}
	if lastErr == nil {
		lastErr = context.Canceled
	}
	return 0, lastErr
}

func SyncLoop(ctx context.Context, logger *zap.Logger, servers []string, interval time.Duration, out *Offset) {
	if out == nil {
		return
	}
	if interval <= 0 {
		interval = 23 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		off, err := SyncOnce(ctx, logger, servers, 3*time.Second)
		if err == nil {
			out.Store(off)
			if logger != nil {
				logger.Info("ntp offset updated", zap.Duration("offset", off))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

