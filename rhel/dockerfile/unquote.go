package dockerfile

import (
	"unicode/utf8"

	"golang.org/x/text/transform"
)

// Unquote is a text transformer that undoes one level of quoting.
//
// It does not enforce that the entire text passed to the Transform method is a
// valid quoted string; leading or trailing characters or multiple consecutive
// quoted strings are fine.
//
// Any unrecognized escape pairs are passed through unchanged. Multicharacter
// escape sequences like "\xNN" or "\NNN" or "\uNNNN" are unsupported.
type Unquote struct {
	state unquoteState
	esc   bool

	escchar rune
}

// NewUnquote returns an Unquote ready to use with the escape metacharacter set
// to '\'.
func NewUnquote() *Unquote {
	return &Unquote{
		escchar: '\\',
	}
}

// Escape changes the escape metacharacter.
//
// This is possible to do at any time, but may be inadvisable.
func (u *Unquote) Escape(r rune) {
	u.escchar = r
}

// Assert that this is a Transformer.
var _ transform.Transformer = (*Unquote)(nil)

// Reset implements transform.Transformer.
func (u *Unquote) Reset() {
	u.esc = false
	u.state = unquoteBare
}

// Transform implements transform.Transformer.
func (u *Unquote) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	r, sz := rune(0), 0
	for ; nSrc < len(src); nSrc += sz {
		r, sz = utf8.DecodeRune(src[nSrc:])
		if r == utf8.RuneError {
			err = transform.ErrShortSrc
			return
		}
		if len(dst) == nDst {
			err = transform.ErrShortDst
			return
		}
		switch u.state {
		case unquoteBare:
			switch {
			case !u.esc && r == u.escchar:
				u.esc = true
				continue
			case !u.esc && r == '"':
				u.state = unquoteDQuote
				continue
			case !u.esc && r == '\'':
				u.state = unquoteSQuote
				continue
			case u.esc && r == '"':
				u.esc = false
			case u.esc && r == '\'':
				u.esc = false
			case u.esc && r == u.escchar:
				u.esc = false
			case u.esc:
				u.esc = false
				// Add in the omitted escape rune.
				nDst += utf8.EncodeRune(dst[nDst:], u.escchar)
			}
		case unquoteSQuote:
			switch {
			case !u.esc && r == u.escchar:
				u.esc = true
				continue
			case !u.esc && r == '\'':
				u.state = unquoteBare
				continue
			case u.esc && r == '\'':
				u.esc = false
			case u.esc && r == u.escchar:
				u.esc = false
			case u.esc:
				u.esc = false
				// Add in the omitted escape rune.
				nDst += utf8.EncodeRune(dst[nDst:], u.escchar)
			}
		case unquoteDQuote:
			switch {
			case !u.esc && r == u.escchar:
				u.esc = true
				continue
			case !u.esc && r == '"':
				u.state = unquoteBare
				continue
			case u.esc && r == '"':
				u.esc = false
			case u.esc && r == u.escchar:
				u.esc = false
			case u.esc:
				u.esc = false
				if r, ok := escTable[r]; ok {
					nDst += utf8.EncodeRune(dst[nDst:], r)
					continue
				}
				nDst += utf8.EncodeRune(dst[nDst:], u.escchar)
			}
		default:
			panic("state botch")
		}
		nDst += utf8.EncodeRune(dst[nDst:], r)
	}
	return nDst, nSrc, nil
}

// UnquoteState tracks the current state of the transformer.
type unquoteState uint8

const (
	// In a bare string: both quotes can be escaped, along with the
	// metacharacter.
	unquoteBare unquoteState = iota
	// In a single-quoted string: single quote and the metacharacter can be
	// escaped.
	unquoteSQuote
	// In a double-quoted string: double quote, the metacharacter, and the usual
	// suspects of C-style escapes are escaped.
	unquoteDQuote
)

// EscTable is a mapping of common single-letter escapes to their "real"
// encodings.
//
// Explicitly-encoded characters (e.g. \000, \x00, \u0000) are not handled here.
// '?' is omitted because it's trigraph braindamage and an explicitly encoded
// character.
//
// See also ascii(7).
var escTable = map[rune]rune{
	'0': 0x00,
	'a': 0x07,
	'b': 0x08,
	't': 0x09,
	'n': 0x0a,
	'v': 0x0b,
	'f': 0x0c,
	'r': 0x0d,
	// 'e' is omitted because it's almost always used to construct other escape
	// sequences for terminals and the like.
}
