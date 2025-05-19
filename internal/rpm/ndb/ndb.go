package ndb

import (
	"context"
	"encoding/binary"
	"io"
)

var le = binary.LittleEndian

// Used throughout the various DBs.
const (
	slotSize  = 4 * 4
	slotStart = 2
)

// CheckMagic reports whether the Reader starts with a magic header for
// a file format supported by this package.
func CheckMagic(_ context.Context, r io.Reader) bool {
	const (
		xdb = 'R' | 'p'<<8 | 'm'<<16 | 'X'<<24
		pkg = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	)
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return false
	}
	m := le.Uint32(b)
	return m == xdb || m == pkg
}
