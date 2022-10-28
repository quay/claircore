package ovalutil

import (
	"io"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

var (
	gzipPool sync.Pool
	zstdPool sync.Pool
)

func getGzip(r io.Reader) (*gzip.Reader, error) {
	z := gzipPool.Get().(*gzip.Reader)
	if z == nil {
		return gzip.NewReader(r)
	}
	if err := z.Reset(r); err != nil {
		return nil, err
	}
	return z, nil
}

func putGzip(z *gzip.Reader) {
	gzipPool.Put(z)
}

func getZstd(r io.Reader) (*zstd.Decoder, error) {
	z := zstdPool.Get().(*zstd.Decoder)
	if z == nil {
		return zstd.NewReader(r)
	}
	if err := z.Reset(r); err != nil {
		return nil, err
	}
	return z, nil
}

func putZstd(z *zstd.Decoder) {
	zstdPool.Put(z)
}
