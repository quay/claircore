// Package bdb provides support for read-only access to an RPM database using the
// BerkeleyDB "hash" format.
package bdb

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/quay/zlog"
)

// CheckMagic looks at bit of the provided Reader to see if it looks like a
// BerkeleyDB file.
//
// According to the libmagic database I looked at:
//
//	# Hash 1.85/1.86 databases store metadata in network byte order.
//	# Btree 1.85/1.86 databases store the metadata in host byte order.
//	# Hash and Btree 2.X and later databases store the metadata in host byte order.
//
// Since this process can't (and doesn't want to) know the endian-ness of the
// layer's eventual host, we just look both ways for the one type we support.
func CheckMagic(ctx context.Context, r io.Reader) bool {
	const Hash = 0x00061561
	// Most hosts are still x86, try LE first.
	ord := []binary.ByteOrder{binary.LittleEndian, binary.BigEndian}
	b := make([]byte, 16)

	if _, err := io.ReadFull(r, b); err != nil {
		zlog.Warn(ctx).Err(err).Msg("unexpected error checking magic")
		return false
	}
	// Look at position 12 for a magic number.
	for _, o := range ord {
		if o.Uint32(b[12:]) == Hash {
			return true
		}
	}
	return false
}
