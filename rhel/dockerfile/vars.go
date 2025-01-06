package dockerfile

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
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
	nullMod   bool
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
	v.expand = varExpandSimple
	v.esc = false
	v.nullMod = false
	v.varName.Reset()
	v.varExpand.Reset()
}

// Transform implements transform.Transformer.
func (v *Vars) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
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
				v.varName.Reset()
				v.varExpand.Reset()
				v.state = varBegin
				v.nullMod = false
				continue
			}
			nDst += utf8.EncodeRune(dst[nDst:], r)
		case varBegin:
			// This arm is one rune beyond the metacharacter.
			v.expand = varExpandSimple
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
				v.nullMod = true
				continue
			case '/': // Non-POSIX: substitutions
				return nDst, nSrc, fmt.Errorf("dockerfile: bad expansion of %q: pattern substitution unsupported", v.varName.String())
			case '=':
				v.expand = varSetDefault
			case '-':
				v.expand = varExpandDefault
			case '+':
				v.expand = varExpandAlternate
			case '?':
				v.expand = varErrIfUnset
			case '%', '#':
				switch r {
				case '%': // suffix
					v.expand = varTrimSuffix
				case '#': // prefix
					v.expand = varTrimPrefix
				default:
					panic("unreachable")
				}
				// If doubled, consume the next rune as well and set greedy mode.
				if peek, psz := utf8.DecodeRune(src[nSrc+sz:]); peek == r {
					sz += psz
					v.expand++
				}
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
			// Check if the expansion mode should have the modified null handling.
			if (r == '-' || r == '+' || r == '?' || r == '=') && v.nullMod {
				v.expand++
				v.nullMod = false
			}
			// If one of the valid expansion modifiers, jump to the next state.
			if r == '-' || r == '+' || r == '?' || r == '=' || r == '%' || r == '#' {
				v.state = varBraceExpand
			}
			// If the code ever gets here, there's a rogue colon.
			if v.nullMod {
				return nDst, nSrc, fmt.Errorf("dockerfile: bad expansion of %q: rogue colon", v.varName.String())
			}
		case varBraceExpand:
			// This arm begins on the rune after the expansion specifier.
			if r != '}' {
				v.varExpand.WriteRune(r)
				continue
			}
			n, done := v.emit(dst[nDst:])
			switch {
			case !done:
				nSrc += sz
				v.state = varEmit
				return nDst, nSrc, transform.ErrShortDst
			case v.state == varError:
				return nDst, nSrc, fmt.Errorf("dockerfile: bad expansion of %q: %s (%v)",
					v.varName.String(),
					v.varExpand.String(),
					v.expand,
				)
			}
			nDst += n
			v.state = varConsume
		default:
			panic("state botch")
		}
	}
	if v.esc {
		// Ended in a "bare" escape character. Just pass it through.
		nDst += utf8.EncodeRune(dst[nDst:], v.escchar)
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
	// Names from the POSIX explanation of shell parameter expansion.
	param := v.varName.String()
	word := v.varExpand.String()
	val, ok := v.v[param]
	switch v.expand {
	case varExpandSimple: // Use what's returned from the lookup.
	case varExpandDefault: // Use "parameter" if set, "word" if not.
		if !ok {
			val = word
		}
	case varExpandDefaultNull: // Use "parameter" if set, "word" if not or set to null.
		if !ok || val == "" {
			val = word
		}
	case varExpandAlternate: // Use "word" if set.
		if ok {
			val = word
		}
	case varExpandAlternateNull: // Use "word" if set and not null.
		if ok && val != "" {
			val = word
		}
	case varErrIfUnset: // Report an error if unset.
		if !ok {
			v.state = varError
			return 0, true
		}
	case varErrIfUnsetNull: // Report an error if unset or null.
		if !ok || val == "" {
			v.state = varError
			return 0, true
		}
	case varSetDefault, varSetDefaultNull:
		switch v.expand {
		case varSetDefault: // Set param if unset.
			if !ok {
				v.v[param] = word
			}
		case varSetDefaultNull: // Set "param" if unset or null.
			if !ok || val == "" {
				v.v[param] = word
			}
		default:
			panic("unreachable")
		}
		v.expand = varExpandSimple
		return v.emit(dst)
	case varTrimPrefix, varTrimPrefixGreedy, varTrimSuffix, varTrimSuffixGreedy:
		greedy := v.expand == varTrimPrefixGreedy || v.expand == varTrimSuffixGreedy
		suffix := v.expand == varTrimSuffix || v.expand == varTrimSuffixGreedy
		re, err := convertPattern([]byte(word), greedy, suffix)
		if err != nil {
			v.state = varError
			return 0, true
		}
		ms := re.FindStringSubmatch(val)
		switch len(ms) {
		case 0, 1:
			// No match, do nothing.
		case 2:
			if suffix {
				val = strings.TrimSuffix(val, ms[1])
			} else {
				val = strings.TrimPrefix(val, ms[1])
			}
		default:
			panic(fmt.Sprintf("pattern compiler is acting up; got: %#v", ms))
		}
	default:
		panic("expand state botch")
	}
	if dstSz < len(val) {
		return 0, false
	}
	n := copy(dst, val)
	return n, true
}

// ConvertPattern transforms "pat" from (something like) the POSIX sh pattern
// language to a regular expression, then returns the compiled regexp.
//
// The resulting regexp reports the prefix/suffix to be removed as the first
// submatch when executed.
//
// This conversion is tricky, because extra hoops are needed to work around the
// leftmost-first behavior.
func convertPattern(pat []byte, greedy bool, suffix bool) (_ *regexp.Regexp, err error) {
	var rePat strings.Builder
	rePat.Grow(len(pat) * 2) // 🤷
	// This is needed to "push" a suffix pattern to the correct place. Note that
	// the "greediness" is backwards: this is the input that's _not_ the
	// pattern.
	pad := `(?:.*)`
	if greedy {
		pad = `(?:.*?)`
	}

	rePat.WriteByte('^')
	if suffix {
		rePat.WriteString(pad)
	}
	rePat.WriteByte('(')
	off := 0
	r, sz := rune(0), 0
	for ; off < len(pat); off += sz {
		r, sz = utf8.DecodeRune(pat[off:])
		if r == utf8.RuneError {
			err = fmt.Errorf("dockerfile: bad pattern %q", pat)
			return
		}
		switch r {
		case '*': // Kleene star
			rePat.WriteString(`.*`)
			if !suffix && !greedy {
				rePat.WriteByte('?')
			}
		case '?': // Single char
			rePat.WriteByte('.')
		case '\\':
			peek, psz := utf8.DecodeRune(pat[off+sz:])
			switch peek {
			case '*', '?', '\\':
				// These are metacharacters in both languages, so the escapes should be passed through.
				rePat.WriteRune(r)
				rePat.WriteRune(peek)
				sz += psz
			case '}', '/':
				// For these escapes, just skip the escape char: we want the literal.
				// Handle slash-escapes, even though we don't support unanchored replacements.
			default:
				return nil, fmt.Errorf(`dockerfile: bad escape '\%c' in pattern %q`, peek, pat)
			}
		case '$', '(', ')', '+', '.', '[', ']', '^', '{', '|', '}': // Regexp metacharacters
			rePat.WriteByte('\\')
			fallthrough
		default:
			rePat.WriteRune(r)
		}
	}
	rePat.WriteByte(')')
	if !suffix {
		rePat.WriteString(pad)
	}
	rePat.WriteByte('$')

	return regexp.Compile(rePat.String())
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
	varError
)

// VarExpand tracks how the current brace expression expects to be expanded.
type varExpand uint8

const (
	varExpandSimple        varExpand = iota // simple expansion
	varExpandDefault                        // default expansion
	varExpandDefaultNull                    // default+null expansion
	varSetDefault                           // set default
	varSetDefaultNull                       // set default, incl. null
	varExpandAlternate                      // alternate expansion
	varExpandAlternateNull                  // alternate expanxion, incl. null
	varErrIfUnset                           // error if unset
	varErrIfUnsetNull                       // error if unset or null
	varTrimSuffix                           // trim suffix
	varTrimSuffixGreedy                     // greedy trim suffix
	varTrimPrefix                           // trim prefix
	varTrimPrefixGreedy                     // greedy trim prefix
)
