// Package urn implements RFC 8141, with additional Namespace Specific (NSS)
// handling for claircore's use cases.
package urn

import (
	"fmt"
	"net/url"
	"strings"
)

// URN is an RFC 8141 URN.
type URN struct {
	// NID is the namespace ID.
	NID string
	// NSS is the namespace specific string.
	NSS string
	// The "R" component is for "resolver" parameters, and have no RFC-defined
	// semantics.
	r string
	// The "Q" component is parameters for the named resource or system.
	q string
	// The "F" component is for clients, as in RFC 3986.
	f string
}

//go:generate sh ./generate.sh

// Parse parses the provided string into its components.
//
// The optional "r", "q", and "f" components are not eagerly processed and are
// only checked for syntactical correctness on demand.
func Parse(n string) (u URN, _ error) {
	n = escape(n)
	if err := parse(&u, n); err != nil {
		return u, fmt.Errorf("urn: %w", err)
	}
	return u, nil
}

func (u *URN) setNID(s string) {
	u.NID = strings.ToLower(s)
}

func (u *URN) setNSS(s string) {
	var n int
	// Remap lower-case hex digits to upper-case.
	f := func(r rune) rune {
		if n != 0 {
			if r > 0x60 && r < 0x67 {
				r -= 0x20
			}
			n--
		}
		if r == '%' {
			n = 2
		}
		return r
	}
	u.NSS = strings.Map(f, s)
}

// String returns the normalized URN with optional components.
func (u *URN) String() string {
	var b strings.Builder
	b.WriteString(`urn:`)
	b.WriteString(u.NID)
	b.WriteByte(':')
	b.WriteString(u.NSS)
	if u.r != "" {
		r, _ := u.R()
		b.WriteString(`?+`)
		b.WriteString(r.Encode())
	}
	if u.q != "" {
		q, _ := u.Q()
		b.WriteString(`?=`)
		b.WriteString(q.Encode())
	}
	if u.f != "" {
		b.WriteByte('#')
		b.WriteString(u.f)
	}
	return b.String()
}

// Normalized returns the normalized URN without optional components.
func (u URN) Normalized() string { return `urn:` + u.NID + `:` + u.NSS }

// R returns the "r" (`?+`) component.
func (u *URN) R() (url.Values, error) { return url.ParseQuery(u.r) }

// Q returns the "q" (`?=`) component.
func (u *URN) Q() (url.Values, error) { return url.ParseQuery(u.q) }

// F returns the "f" (`#`) component.
func (u *URN) F() string { return u.f }

// Equal checks for equivalence as described in RFC 8141.
func (u *URN) Equal(b *URN) bool { return u.NID == b.NID && u.NSS == b.NSS }

// Name returns a claircore name.
//
// Reports an error if the URN is not in the "claircore" namespace.
func (u *URN) Name() (Name, error) {
	if u.NID != "claircore" {
		return Name{}, fmt.Errorf(`urn: wrong nid: %q`, u.NID)
	}

	fs := strings.FieldsFunc(u.NSS, isColon)
	if len(fs) < 3 {
		return Name{}, fmt.Errorf(`urn: bad format for nss: %q`, fs)
	}
	var n Name
	n.System = fs[0]
	n.Kind = fs[1]
	n.Name = fs[2]

	if u.q != "" {
		q, err := u.Q()
		if err != nil {
			return Name{}, fmt.Errorf(`urn: invalid q-component: %w`, err)
		}
		for _, x := range []struct {
			Key string
			Tgt **string
		}{
			{"version", &n.Version},
		} {
			if vs, ok := q[x.Key]; ok {
				(*x.Tgt) = &vs[0]
			}
		}
	}

	return n, nil
}

func isColon(r rune) bool {
	return r == ':'
}

// Normalize returns the normalized version of the passed URN.
func Normalize(n string) (string, error) {
	u, err := Parse(n)
	if err != nil {
		return "", err
	}
	return u.Normalized(), nil
}
