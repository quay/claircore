package dockerfile

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/transform"
)

// Vars is a text transformer that does variable expansion as described in the
// Dockerfile Reference document.
//
// It supports POSIX sh-like expansions but not in the general forms, only the
// ":-" (expand if unset) and ":+" (expand if set) versions.
//
// The transformation algorithm uses an escape metacharacter in front of the
// variable metacharacter to allow a literal metacharacter to be passed through.
// Any unrecognized escapes are passed through unmodified.
type Vars struct {
	v       map[string]string
	escchar rune

	state     varState
	expand    varExpand
	esc       bool
	varName   strings.Builder
	varExpand strings.Builder
}

// NewVars returns a Vars with the metacharacter set to '\' and no variables
// defined.
func NewVars() *Vars {
	v := Vars{
		escchar: '\\',
		v:       make(map[string]string),
	}
	v.Reset()
	return &v
}

// Escape changes the escape metacharacter.
//
// This is possible to do at any time, but may be inadvisable.
func (v *Vars) Escape(r rune) {
	v.escchar = r
}

// Set sets the variable "key" to "val".
func (v *Vars) Set(key, val string) {
	v.v[key] = val
}

// Clear unsets all variables.
func (v *Vars) Clear() {
	v.v = make(map[string]string)
}

// Assert that this is a Transformer.
var _ transform.Transformer = (*Vars)(nil)

// Reset implements transform.Transformer.
//
// This method does not reset calls to Set. Use Clear to reset stored variable
// expansions.
func (v *Vars) Reset() {
	v.state = varConsume
	v.expand = varExNone
	v.esc = false
	v.varName.Reset()
	v.varExpand.Reset()
}

// Transform implements transform.Transformer.
func (v *Vars) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	varStart := -1
	r, sz := rune(0), 0
	if v.state == varEmit {
		// If we're here, we need to emit first thing.
		var done bool
		n, done := v.emit(dst)
		if !done {
			return 0, 0, transform.ErrShortDst
		}
		v.state = varConsume
		return n, 0, nil
	}
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
		switch v.state {
		case varConsume:
			// Copy runes until there's an interesting one. This arm is the only
			// one that deals with escape handling.
			switch {
			case !v.esc && r == v.escchar:
				v.esc = true
				continue
			case v.esc && r == VarMeta:
				v.esc = false
			case v.esc: // Odd escape sequence, so just add back in the escape.
				v.esc = false
				nDst += utf8.EncodeRune(dst[nDst:], v.escchar)
			case r == VarMeta:
				// Record current position in case the destination is too small
				// and the process backs out.
				varStart = nSrc + sz
				v.varName.Reset()
				v.varExpand.Reset()
				v.state = varBegin
				continue
			}
			nDst += utf8.EncodeRune(dst[nDst:], r)
		case varBegin:
			// This arm is one rune beyond the metacharacter.
			v.expand = varExNone
			if r == '{' {
				v.state = varBraceName
				continue
			}
			v.state = varBareword
			sz = 0 // Re-handle this rune.
		case varBareword:
			// This arm handles a bare variable, so no special expansion or
			// braces.
			if validName(r) {
				v.varName.WriteRune(r)
				continue
			}
			sz = 0 // Re-handle this rune.
			n, done := v.emit(dst[nDst:])
			if !done {
				nSrc += sz
				v.state = varEmit
				return nDst, nSrc, transform.ErrShortDst
			}
			nDst += n
			v.state = varConsume
		case varBraceName:
			// This arm begins on the rune after the opening brace.
			switch r {
			case ':':
				// POSIX variable expansion has ':' as a modifier on the forms
				// of expansion ('-', '=', '+'), but the Dockerfile reference
				// only mentions ':-' and ':+'.
				peek, psz := utf8.DecodeRune(src[nSrc+sz:])
				switch peek {
				case '-':
					v.expand = varExDefault
				case '+':
					v.expand = varExIfSet
				default:
					nSrc = varStart
					return nDst, nSrc, fmt.Errorf("bad default spec at %d", nSrc+sz)
				}
				sz += psz
				v.state = varBraceExpand
			case '}':
				n, done := v.emit(dst[nDst:])
				if !done {
					nSrc += sz
					v.state = varEmit
					return nDst, nSrc, transform.ErrShortDst
				}
				nDst += n
				v.state = varConsume
			default:
				v.varName.WriteRune(r)
			}
		case varBraceExpand:
			// This arm begins on the rune after the expansion specifier.
			if r != '}' {
				v.varExpand.WriteRune(r)
				continue
			}
			n, done := v.emit(dst[nDst:])
			if !done {
				nSrc += sz
				v.state = varEmit
				return nDst, nSrc, transform.ErrShortDst
			}
			nDst += n
			v.state = varConsume
		default:
			panic("state botch")
		}
	}
	if v.state == varBareword && atEOF {
		// Hit EOF, so variable name is complete.
		n, done := v.emit(dst[nDst:])
		if !done {
			v.state = varEmit
			return nDst, nSrc, transform.ErrShortDst
		}
		nDst += n
	}
	return nDst, nSrc, nil
}

// ValidName tests whether the rune is valid in a variable name.
func validName(r rune) bool {
	return unicode.In(r, unicode.Letter, unicode.Digit) || r == '_' || r == '-'
}

// Emit writes out the expanded variable, using state accumulated in the
// receiver. It does not reset state. It reports 0, false if there was not
// enough space in dst.
func (v *Vars) emit(dst []byte) (int, bool) {
	dstSz := len(dst)
	var w string
	res, ok := v.v[v.varName.String()]
	switch v.expand {
	case varExNone: // Use what's returned from the lookup.
		w = res
	case varExDefault: // Use lookup or default.
		if ok {
			w = res
			break
		}
		w = v.varExpand.String()
	case varExIfSet: // Use the expando or nothing.
		if ok {
			w = v.varExpand.String()
		}
	default:
		panic("expand state botch")
	}
	if dstSz < len(w) {
		return 0, false
	}
	n := copy(dst, w)
	return n, true
}

// Assert that this is a SpanningTransformer.
var _ transform.SpanningTransformer = (*Vars)(nil)

// Span implements transform.SpanningTransfomer.
//
// Callers can use this to avoid copying.
func (v *Vars) Span(src []byte, atEOF bool) (int, error) {
	// Look for meta.
	i := bytes.IndexFunc(src, v.findMeta)
	if i == -1 {
		return len(src), nil
	}
	r, sz := utf8.DecodeRune(src[i:])
	_, lsz := utf8.DecodeLastRune(src)
	li := len(src) - lsz
	switch {
	case i == li && atEOF && r == v.escchar:
		// Last rune was an escchar there's nothing else.
		return i, errors.New("dangling escape")
	case i == li && atEOF && r == VarMeta:
		// Last rune was a meta there's nothing else.
		return i, errors.New("dangling metacharacter")
	case i == li && !atEOF:
		// Last rune was an escchar or meta and there's more.
		return li, transform.ErrEndOfSpan
	case r == VarMeta:
	default:
		// Peek at the next rune to see if it's a valid escape.
		nr, nsz := utf8.DecodeRune(src[i+sz:])
		if r == v.escchar && nr == VarMeta {
			// transforming escape
			break
		}
		off := i + sz + nsz
		n, err := v.Span(src[off:], atEOF)
		n += off
		return n, err
	}
	return i, transform.ErrEndOfSpan
}

// FindMeta is meant to be used with bytes.IndexFunc. It returns true on the
// first possible meta character. Depending on the direction, the character may
// be escaped.
func (v *Vars) findMeta(r rune) bool {
	return r == v.escchar || r == VarMeta
}

// VarMeta is the metacharacter for variables. It's not configurable.
const VarMeta = '$'

// VarState tracks what state the variable transformer is in.
type varState uint8

const (
	varConsume varState = iota
	varBegin
	varBareword
	varBraceName
	varBraceExpand
	varEmit
)

// VarExpand tracks how the current brace expression expects to be expanded.
type varExpand uint8

const (
	// Expand to the named variable or the empty string.
	varExNone varExpand = iota
	// Expand to the named variable or the provided word.
	varExDefault
	// Expand to the provided word or the empty string.
	varExIfSet
)
