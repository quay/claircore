// Package tarfs implements the [fs.FS] interface over a tar archive.
//
// It also implements the [fs.FS] interface over the tar-compatible [eStargz] and [zstd:chunked] formats.
// This package does not support newer [eStargz] layers with the `innerOffset` field.
//
// [eStargz]: https://github.com/containerd/stargz-snapshotter/blob/main/docs/estargz.md
// [zstd:chunked]: https://github.com/containers/image/pull/1084
package tarfs

import (
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NormPath removes relative elements and enforces that the resulting string is
// utf8-clean.
//
// This is needed any time a name is pulled from the archive.
func normPath(p string) string {
	s, _ := filepath.Rel("/", filepath.Join("/", p))
	if utf8.ValidString(s) {
		return s
	}
	// Slow path -- need to decode the string and write out escapes.
	// This is roughly modeled on [strings.ToValidUTF8], but without the run
	// coalescing and the replacement is based on the invalid byte sequence. The
	// [strings.ToValidUTF8] function only cares if the encoding is valid, not
	// if it's a valid codepoint.
	var b strings.Builder
	b.Grow(len(s) + 3) // We already know we'll need at least one replacement, which are 4 bytes.
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			b.WriteByte(c)
			continue
		}
		// May be a valid multibyte rune.
		r, w := utf8.DecodeRuneInString(s[i:])
		if r != utf8.RuneError {
			i += w
			b.WriteRune(r)
			continue
		}
		for n := 0; n < w; n++ {
			c := uint8(s[i+n])
			b.WriteString(`\x`)
			b.WriteString(strconv.FormatUint(uint64(c), 16))
		}
		i += w
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Possible values for the "magic" in a tar header.
var (
	magicPAX    = []byte("ustar\x00")
	magicGNU    = []byte("ustar ")
	magicOldGNU = []byte("ustar  \x00")
)

// Where the "magic" value lives.
const magicOff = 257
