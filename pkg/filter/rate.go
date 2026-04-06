package filter

import (
	"sync"
	"time"
)

type tokenBucket struct {
	tokens     float64
	rate       float64 // tokens per second
	burst      float64 // max tokens (= rate, i.e. 1 second burst)
	lastRefill time.Time
}

func newTokenBucket(rate float64) *tokenBucket {
	return &tokenBucket{
		tokens:     rate,
		rate:       rate,
		burst:      rate,
		lastRefill: time.Now(),
	}
}

func (tb *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}
	tb.lastRefill = now

	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// RateLimiter provides per-MAC and per-client rate limiting.
type RateLimiter struct {
	mu        sync.Mutex
	perMAC    map[string]*tokenBucket
	perClient *tokenBucket
	macRate   float64
	// cleanup tracking
	macLastSeen map[string]time.Time
}

// NewRateLimiter creates a rate limiter. Pass 0 to disable a limit.
func NewRateLimiter(perMACRate, perClientRate float64) *RateLimiter {
	rl := &RateLimiter{
		macRate: perMACRate,
	}
	if perMACRate > 0 {
		rl.perMAC = make(map[string]*tokenBucket)
		rl.macLastSeen = make(map[string]time.Time)
	}
	if perClientRate > 0 {
		rl.perClient = newTokenBucket(perClientRate)
	}
	return rl
}

// Allow checks per-MAC first, then per-client.
// A spammy MAC gets capped at its own limit without consuming the client's total budget.
func (rl *RateLimiter) Allow(srcMAC string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Per-MAC check first — drop before consuming per-client tokens
	if rl.perMAC != nil {
		tb, ok := rl.perMAC[srcMAC]
		if !ok {
			tb = newTokenBucket(rl.macRate)
			rl.perMAC[srcMAC] = tb
			if len(rl.perMAC) > 1000 {
				rl.evictStale()
			}
		}
		rl.macLastSeen[srcMAC] = time.Now()
		if !tb.allow() {
			return false
		}
	}

	// Per-client check — caps total across all MACs
	if rl.perClient != nil && !rl.perClient.allow() {
		return false
	}

	return true
}

func (rl *RateLimiter) evictStale() {
	cutoff := time.Now().Add(-60 * time.Second)
	for mac, last := range rl.macLastSeen {
		if last.Before(cutoff) {
			delete(rl.perMAC, mac)
			delete(rl.macLastSeen, mac)
		}
	}
}
