package tarfs

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// TODO(hank) Remove these wrapper functions when a generic sync.Pool lands.

// GetCopyBuf pulls a buffer from the pool.
func getCopyBuf() []byte {
	b := bufpool.Get()
	if b == nil {
		// Allocate 1 MiB buffers to start.
		// This is much too big for small files and much too small for big files.
		return make([]byte, 1024*1024)
	}
	return b.([]byte)
}

// PutCopyBuf returns a buffer to the pool.
func putCopyBuf(b []byte) { bufpool.Put(b) }

// Getzstd pulls an initialized decoder from the pool.
func getZstd() *zstd.Decoder {
	d := zstdpool.Get()
	if d == nil {
		var err error
		if d, err = zstd.NewReader(nil); err != nil {
			// Should *never* happen -- a nil Reader causes only internal setup allocations.
			panic(fmt.Sprintf("error creating zstd reader: %v", err))
		}
	}
	return d.(*zstd.Decoder)
}

// PutZstd returns a decoder to the pool.
func putZstd(d *zstd.Decoder) { zstdpool.Put(d) }

// GetGzip pulls an initialized reader from the pool.
func getGzip() *gzip.Reader {
	r := gzippool.Get()
	if r == nil {
		return new(gzip.Reader)
	}
	return r.(*gzip.Reader)
}

// PutGzip returns a reader to the pool.
func putGzip(r *gzip.Reader) { gzippool.Put(r) }

// Package-level pools for the respective objects.
var (
	bufpool  sync.Pool
	zstdpool sync.Pool
	gzippool sync.Pool
)
