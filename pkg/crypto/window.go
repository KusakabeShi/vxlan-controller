package crypto

import "sync"

const replayWindowSize = 2048

type SlidingWindow struct {
	mu     sync.Mutex
	bitmap [replayWindowSize / 8]byte // 2048 bits
	top    uint64                     // highest counter seen
	inited bool
}

func NewSlidingWindow() *SlidingWindow { return &SlidingWindow{} }

func (w *SlidingWindow) Accept(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.inited {
		w.inited = true
		w.top = counter
		w.setBitLocked(counter)
		return true
	}

	if counter > w.top {
		shift := counter - w.top
		if shift >= replayWindowSize {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			w.shiftLocked(int(shift))
		}
		w.top = counter
		w.setBitLocked(counter)
		return true
	}

	// counter <= top
	if w.top-counter >= replayWindowSize {
		return false
	}
	if w.getBitLocked(counter) {
		return false
	}
	w.setBitLocked(counter)
	return true
}

func (w *SlidingWindow) idxBitLocked(counter uint64) (byteIdx int, bitMask byte) {
	off := w.top - counter
	bit := int(off)
	byteIdx = bit / 8
	bitMask = 1 << uint(bit%8)
	return
}

func (w *SlidingWindow) getBitLocked(counter uint64) bool {
	byteIdx, mask := w.idxBitLocked(counter)
	return (w.bitmap[byteIdx] & mask) != 0
}

func (w *SlidingWindow) setBitLocked(counter uint64) {
	byteIdx, mask := w.idxBitLocked(counter)
	w.bitmap[byteIdx] |= mask
}

func (w *SlidingWindow) shiftLocked(shift int) {
	if shift <= 0 {
		return
	}
	byteShift := shift / 8
	bitShift := uint(shift % 8)

	if byteShift > 0 {
		for i := len(w.bitmap) - 1; i >= 0; i-- {
			src := i - byteShift
			if src >= 0 {
				w.bitmap[i] = w.bitmap[src]
			} else {
				w.bitmap[i] = 0
			}
		}
	}
	if bitShift == 0 {
		return
	}
	var carry byte
	for i := len(w.bitmap) - 1; i >= 0; i-- {
		b := w.bitmap[i]
		newCarry := b << (8 - bitShift)
		w.bitmap[i] = (b >> bitShift) | carry
		carry = newCarry
	}
}
