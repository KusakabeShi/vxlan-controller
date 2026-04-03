package crypto

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
)

// REJECT_AFTER_MESSAGES is the max counter before requiring rekey.
const REJECT_AFTER_MESSAGES = uint64(1) << 60

var ErrCounterExhausted = errors.New("nonce counter exhausted, rekey required")

// NonceCounter is a thread-safe counter for ChaCha20-Poly1305 nonces.
type NonceCounter struct {
	counter atomic.Uint64
}

// Next returns the next nonce (12 bytes: 4 zero + 8 LE counter).
func (nc *NonceCounter) Next() ([12]byte, error) {
	c := nc.counter.Add(1) - 1
	if c >= REJECT_AFTER_MESSAGES {
		return [12]byte{}, ErrCounterExhausted
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c)
	return nonce, nil
}

// Current returns the current counter value.
func (nc *NonceCounter) Current() uint64 {
	return nc.counter.Load()
}

// MakeNonce creates a 12-byte nonce from a counter value.
func MakeNonce(counter uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// SlidingWindow implements a 2048-bit sliding window for UDP replay protection.
type SlidingWindow struct {
	mu     sync.Mutex
	bitmap [256]byte // 2048 bits
	top    uint64
}

const windowSize = 2048

// Check returns true if the counter is valid (not replayed, not too old).
// If valid, marks it as seen.
func (sw *SlidingWindow) Check(counter uint64) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if counter > sw.top {
		// Advance the window
		diff := counter - sw.top
		if diff >= windowSize {
			// Clear entire bitmap
			for i := range sw.bitmap {
				sw.bitmap[i] = 0
			}
		} else {
			// Clear bits between old top and new top
			for i := uint64(0); i < diff; i++ {
				bitIdx := (sw.top + 1 + i) % windowSize
				sw.bitmap[bitIdx/8] &^= 1 << (bitIdx % 8)
			}
		}
		sw.top = counter
		// Mark current as seen
		bitIdx := counter % windowSize
		sw.bitmap[bitIdx/8] |= 1 << (bitIdx % 8)
		return true
	}

	if sw.top-counter >= windowSize {
		// Too old
		return false
	}

	bitIdx := counter % windowSize
	if sw.bitmap[bitIdx/8]&(1<<(bitIdx%8)) != 0 {
		// Already seen
		return false
	}

	// Mark as seen
	sw.bitmap[bitIdx/8] |= 1 << (bitIdx % 8)
	return true
}

// TCPCounter tracks the expected next counter for TCP (strict increment).
type TCPCounter struct {
	mu       sync.Mutex
	expected uint64
	started  bool
}

// Check validates that the counter is strictly incrementing for TCP.
func (tc *TCPCounter) Check(counter uint64) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if !tc.started {
		tc.started = true
		tc.expected = counter + 1
		return true
	}
	if counter != tc.expected {
		return false
	}
	tc.expected++
	return true
}
