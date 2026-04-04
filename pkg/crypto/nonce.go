package crypto

import "encoding/binary"

func nonce12(counter uint64) [12]byte {
	var nonce [12]byte
	// 32 bits zero + 64-bit little-endian counter
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

