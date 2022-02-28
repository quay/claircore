package cpe

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Attribute is a type for enumerating the valid CPE attributes.
type Attribute int

//go:generate stringer -type Attribute -linecomment

// These are the valid Attributes, in CPE 2.3 binding order.
const (
	Part      Attribute = iota // part
	Vendor                     // vendor
	Product                    // product
	Version                    // version
	Update                     // update
	Edition                    // edition
	Language                   // language
	SwEdition                  // sw_edition
	TargetSW                   // target_sw
	TargetHW                   // target_hw
	Other                      // other
)

// NB This order is different from 2.2 order, and some don't exist in that
// binding. This makes the test cases a little hard to reason about.

// NumAttr is the number of attributes in a 2.3 WFN.
const NumAttr = 11

// NonASCII reports true if the rune is not ASCII.
func nonASCII(r rune) bool {
	return r >= unicode.MaxASCII
}

// Reserved reports true if the rune is in the "reserved" set for CPE
// strings and needs quoting.
func reserved(r rune) bool {
	return (r < 0x30 || r > 0x39) &&
		(r < 0x41 || r > 0x5a) &&
		(r < 0x61 || r > 0x7a) &&
		r != '_'
}

// Validate is adapted from
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf section 5.3.2
func validate(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("cpe: string not valid utf8")
	}
	if strings.IndexFunc(s, nonASCII) != -1 {
		return fmt.Errorf("cpe: string contains non-ASCII characters")
	}
	if strings.IndexFunc(s, unicode.IsSpace) != -1 {
		return fmt.Errorf("cpe: string contains space characters")
	}
	// Special character rules:
	// A single * means ANY and a quoted hyphen would get unquoted, which means
	// NA, so those are disallowed as string values.
	if s == "*" {
		return fmt.Errorf("cpe: single asterisk MUST NOT be used by itself")
	}
	if s == "\\-" {
		return fmt.Errorf("cpe: quoted hyphen MUST NOT be used by itself")
	}
	var (
		// In 'escaped' state
		esc = false
		// position of last rune
		last = len(s) - 1
		// if in a run of ? and if we've seen a non-? character
		qRun, atStart = false, true
	)
	for i, r := range s {
		switch r {
		case '*':
			if esc { // if escaped, it's not special
				break
			}
			if i != 0 && i != last {
				return fmt.Errorf("cpe: invalid position for special character: %q at %d", r, i)
			}
		case '?':
			if esc { // if escaped, it's not special
				break
			}
			qRun = true
		case '\\':
			esc = true
			// skip resetting the esc bool
			continue
		default:
			if reserved(r) && !esc {
				return fmt.Errorf("invalid unquoted character: %q at %d", r, i)
			}
		}
		if r != '?' {
			// The only place valid for a run of '?' is at the beginning and end
			// of a string. So if we read a series of '?' then a non-'?'
			// *twice*, that's invalid.
			if qRun && !atStart {
				return fmt.Errorf("cpe: invalid position for special character: %q at %d", '?', i-1)
			}
			qRun, atStart = false, false
		}
		esc = false
	}
	return nil
}

// Value represents all the states for an attribute's value.
type Value struct {
	V    string
	Kind ValueKind
}

// NewValue constructs a specific value and ensures it's a valid string.
//
// This function does not quote the provided string, only validates that the
// quoting is proper.
func NewValue(v string) (Value, error) {
	if err := validate(v); err != nil {
		return Value{}, err
	}
	return Value{
		Kind: ValueSet,
		V:    v,
	}, nil
}

// ValueKind indicates what "kind" a value is.
type ValueKind uint

//go:generate stringer -type ValueKind

// These are the valid states for a wfn attribute's value.
const (
	ValueUnset ValueKind = iota
	ValueAny
	ValueNA
	ValueSet
)

func (v *Value) String() string {
	var b strings.Builder
	v.bind(&b)
	return b.String()
}

// WFN is a well-formed name as defined by the Common Platform Enumeration (CPE)
// spec: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
//
// This package does not implement binding into URI form.
type WFN struct {
	Attr [NumAttr]Value
}

// Valid reports an error if a WFN is not, in fact, well-formed.
//
// Functions returning a WFN call this before returning, but if a WFN is
// constructed in code, the user should check it via this method.
func (w WFN) Valid() error {
	unset := 0
	for i := 0; i < NumAttr; i++ {
		if err := validate(w.Attr[i].V); err != nil {
			return fmt.Errorf("cpe: wfn attr %v is invalid: %w", Attribute(i), err)
		}
		if v := &w.Attr[i]; v.Kind == ValueUnset {
			unset++
		}
	}
	if unset == NumAttr {
		return ErrUnset
	}
	const (
		app = `a`
		os  = `o`
		hw  = `h`
	)
	if p := w.Attr[int(Part)]; p.Kind == ValueSet {
		if len(p.V) != 1 ||
			(p.V != app && p.V != os && p.V != hw) {
			return fmt.Errorf("cpe: wfn attr %v is invalid: %q is a disallowed value", Part, p.V)
		}
	}
	return nil
}

// ErrUnset is returned from (WFN).Valid() if it is the zero value.
var ErrUnset = errors.New("cpe: wfn is empty")

func (w WFN) String() string {
	return w.BindFS()
}

// These functions are defined in the spec to aid in implementation of other
// algorithms, so they're implemented here in case they're needed.

func (w WFN) get(a Attribute) Value {
	return w.Attr[int(a)]
}

func (w WFN) set(a Attribute, v *Value) WFN {
	r := w
	if v == nil {
		r.Attr[int(a)].Kind = ValueUnset
	} else {
		r.Attr[int(a)] = *v
	}
	return r
}
