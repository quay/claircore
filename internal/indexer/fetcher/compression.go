package fetcher

import (
	"bytes"
)

type compression int

const (
	cmpGzip compression = iota
	cmpZstd
	cmpNone
)

var (
	cmpHeaders = [...][]byte{
		[]byte{0x1F, 0x8B, 0x08},
		[]byte{0x28, 0xB5, 0x2F, 0xFD},
	}
)

func detectCompression(b []byte) compression {
	for c, h := range cmpHeaders {
		if len(b) < len(h) {
			continue
		}
		if bytes.Equal(h, b[:len(h)]) {
			return compression(c)
		}
	}
	return cmpNone
}
