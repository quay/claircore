package tarfs

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// The value we should find in the "magic" position of the tar header.
var (
	magicPAX    = []byte("ustar\x00")
	magicGNU    = []byte("ustar ")
	magicOldGNU = []byte("ustar  \x00")
)

// ErrFormat can be compared via [errors.Is] against errors reported by [New]
// to determine if the tar fail is considered well-formed.
var ErrFormat = errors.New("tarfs: format error reading file")

// ParseErr returns an error that .Is reports true for ErrFormat.
//
// The `%w` verb does not work.
func parseErr(f string, v ...interface{}) error {
	return parseError(fmt.Sprintf(f, v...))
}

type parseError string

func (e parseError) Is(tgt error) bool { return tgt == ErrFormat }
func (e parseError) Error() string     { return string(e) }

// FindSegments looks at a tar blockwise to establish where individual files and
// their headers are stored. Each returned segment describes a region that is
// not a complete tar file, but can have exactly one file read from it.
func findSegments(r io.ReaderAt) ([]segment, error) {
	// Constants and offsets from POSIX.
	const (
		blockSz    = 512
		magicOff   = 257
		versionOff = 263
		typeflag   = 156
		sizeOff    = 124
	)
	b := make([]byte, blockSz)
	var ret []segment
	// Start block of the current segment.
	var cur int64
	// Block number being read.
	var blk int64
	// Has the parser seen a zeroes block.
	var zeroes bool

Scan:
	for {
		off := blk * blockSz
		n, err := r.ReadAt(b, off)
		switch {
		case errors.Is(err, nil) && n != blockSz:
			// Should be impossible with a well-formed archive, so raise an
			// error. Should also be impossible with a conforming [io.ReaderAt].
			return nil, parseErr("short read at offset: %d (got: %d, want: %d)", off, n, blockSz)
		case errors.Is(err, nil): // OK
		case errors.Is(err, io.EOF):
			switch {
			case n == 0:
				// Early EOF on a block boundary. Let it slide.
				//
				// Handle this case because some layers in the wild are a single
				// directory block, with no trailer.
				break Scan
			case n == blockSz:
				// Make sure to process the read, even if EOF was returned.
			default:
				return nil, parseErr("unexpected EOF at %d: %v", off, err)
			}
		default:
			return nil, err
		}

		magic := b[magicOff:][:6]
		zeroBlock := true
		for _, b := range b {
			if b != 0x00 {
				zeroBlock = false
				break
			}
		}
		switch {
		// Tar files end with two blocks of zeroes. These two arms track that.
		case !zeroes && zeroBlock:
			zeroes = true
			continue
		case zeroes && zeroBlock:
			// Check for a valid second zeroes block.
			break Scan
		case zeroes && !zeroBlock:
			// Found the first trailer block, but not the second.
			return nil, parseErr("bad block at %d: expected second trailer block", off)
		// These arms are belt-and-suspenders to make sure we're reading a
		// header block and not a contents block, somehow.
		case bytes.Equal(b[magicOff:][:8], magicOldGNU):
			// OldGNU madness. This arm matching means the headers aren't
			// actually POSIX conforming, but hopefully it's not an issue. Just
			// roll with it. USTAR was standardized in 1988; frankly, it's the
			// creator's fault if something doesn't work right because there's
			// some incompatibility.
		case !bytes.Equal(magic, magicPAX) && !bytes.Equal(magic, magicGNU):
			return nil, parseErr("bad block at %d: got magic %+q", off, magic)
		case !bytes.Equal(b[versionOff:][:2], []byte("00")):
			return nil, parseErr("bad block at %d: got version %+q", off, b[versionOff:][:2])
		}
		encSz := b[sizeOff:][:12]
		sz, err := parseNumber(encSz)
		if err != nil {
			return nil, parseErr("invalid number: %024x: %v", encSz, err)
		}
		nBlk := sz / blockSz
		if sz%blockSz != 0 {
			nBlk++
		}
		blk++       // Current header block
		blk += nBlk // File contents
		switch b[typeflag] {
		case tar.TypeXHeader, tar.TypeGNULongLink, tar.TypeGNULongName, tar.TypeGNUSparse:
			// All these are prepended to a "real" entry.
		case tar.TypeBlock, tar.TypeChar, tar.TypeCont, tar.TypeDir, tar.TypeFifo, tar.TypeLink, tar.TypeReg, tar.TypeRegA, tar.TypeSymlink:
			// Found a data block, emit it:
			ret = append(ret, segment{start: cur * blockSz, size: (blk - cur) * blockSz})
			fallthrough
		default:
			// any blocks not enumerated are not handled.
			cur = blk
		}
	}
	return ret, nil
}

// Segment describes one file in a tar, including relevant headers.
type segment struct {
	start int64
	size  int64
}

// ParseNumber extracts a number from the encoded form in the tar header.
//
// This is based on the internal version in archive/tar.
func parseNumber(b []byte) (int64, error) {
	// If in binary format, decode it.
	if len(b) > 0 && b[0]&0x80 != 0 {
		// See also: src/archive/tar/strconv.go
		// Handling negative numbers relies on the following identity:
		//	-a-1 == ^a
		//
		// If the number is negative, we use an inversion mask to invert the
		// data bytes and treat the value as an unsigned number.
		var inv byte // 0x00 if positive or zero, 0xff if negative
		if b[0]&0x40 != 0 {
			inv = 0xff
		}

		var x uint64
		for i, c := range b {
			c ^= inv // Inverts c only if inv is 0xff, otherwise does nothing
			if i == 0 {
				c &= 0x7f // Ignore signal bit in first byte
			}
			if (x >> 56) > 0 {
				return 0, errors.New("integer overflow")
			}
			x = x<<8 | uint64(c)
		}
		if (x >> 63) > 0 {
			return 0, errors.New("integer overflow")
		}
		if inv == 0xff {
			return ^int64(x), nil
		}
		return int64(x), nil
	}
	// Otherwise, it's stringified.
	b = bytes.Trim(b, " \x00")
	if len(b) == 0 {
		return 0, nil
	}
	n, err := strconv.ParseUint(cstring(b), 8, 63) // Only positive int64 values allowed.
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

// Cstring interprets the byte slice as a C string. If there is no NULL, it
// returns the entire slice as a string.
//
// The entire-slice behavior handles the case where a fixed size header field is
// fully populated.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
