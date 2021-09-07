package java

import (
	"bytes"
	"sync"
)

// Pool is a pool of bytes.Buffers for Scan.
//
// Buffers returned by getBuf have a minimum size of 4MiB to reduce
// reallocations.
var pool sync.Pool

func getBuf() *bytes.Buffer {
	const startSize = 4 * 1024 * 1024 // 4 MiB
	if b, ok := pool.Get().(*bytes.Buffer); ok {
		return b
	}
	var b bytes.Buffer
	b.Grow(startSize)
	return &b
}

func putBuf(b *bytes.Buffer) {
	b.Reset()
	pool.Put(b)
}
