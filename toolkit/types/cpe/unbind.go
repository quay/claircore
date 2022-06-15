package cpe

import (
	"fmt"
	"strings"
)

const (
	cpe22Prefix = `cpe:/`
	cpe23Prefix = `cpe:2.3:`
)

// Unbind attempts to unbind a string regardless of it be a formatted string or
// URI.
func Unbind(s string) (WFN, error) {
	switch {
	case strings.HasPrefix(s, cpe22Prefix):
		return UnbindURI(s)
	case strings.HasPrefix(s, cpe23Prefix):
		return UnbindFS(s)
	default:
	}
	return WFN{}, fmt.Errorf("cpe: string does not appear to be a bound WFN")
}

// MustUnbind calls Unbind on the provided string, but panics if any errors are
// encountered.
//
// This is primarily useful for static data where any error is a programmer
// error.
func MustUnbind(s string) WFN {
	w, err := Unbind(s)
	if err != nil {
		panic(err)
	}
	return w
}

// UnbindURI attempts to unbind a string as CPE 2.2 URI into a WFN.
//
// This function supports unpacking attributes from the "edition" component as
// specified in CPE 2.3.
func UnbindURI(s string) (WFN, error) {
	r := WFN{}
	if !strings.HasPrefix(s, cpe22Prefix) {
		return r, fmt.Errorf("cpe: malformed CPE URI")
	}
	// URI form allows parts to be elided, so set all the standard components to
	// a default of "ANY".
	attrs := [...]Attribute{Part, Vendor, Product, Version, Update, Edition, Language}
	for _, a := range attrs {
		r.Attr[a].Kind = ValueAny
	}
	var b strings.Builder
	// URI form percent-encodes instead of backslash-escaping, so splitting is
	// easier than FS form.
	comp := strings.Split(s, ":")
	// The second component has a slash prefix.
	comp[1] = strings.TrimPrefix(comp[1], "/")
	for i, c := range comp[1:] {
		if i >= len(attrs) {
			return r, fmt.Errorf("cpe: unexpected %dth component", i)
		}
		if i == 5 && strings.HasPrefix(c, "~") {
			attrs := [...]Attribute{Edition, SwEdition, TargetSW, TargetHW, Other}
			for i, c := range strings.SplitN(c, `~`, 6)[1:] {
				r.Attr[attrs[i]].unbindURI(&b, c)
			}
			continue
		}
		r.Attr[attrs[i]].unbindURI(&b, c)
	}
	return r, r.Valid()
}

func (v *Value) unbindURI(b *strings.Builder, s string) {
	if b == nil {
		b = &strings.Builder{}
		b.Grow(len(s))
	}
	b.Reset()
	switch s {
	case ``:
		v.Kind = ValueAny
	case `-`:
		v.Kind = ValueNA
	default:
		v.Kind = ValueSet
		valueURI.WriteString(b, strings.ToLower(s))
		v.V = b.String()
	}
}

// ValueURI is a replace that undoes the URI percent encoding.
var valueURI = strings.NewReplacer(
	`.`, `\.`,
	`-`, `\-`,
	`~`, `\~`,
	// The specified algorithm sticks validation logic for * and ? in the
	// unquoting. We skip that and just make sure to validate later.
	`%01`, `?`,
	`%02`, `*`,
	`%21`, `\!`,
	`%22`, `\"`,
	`%23`, `\#`,
	`%24`, `\$`,
	`%25`, `\%`,
	`%26`, `\&`,
	`%27`, `\'`,
	`%28`, `\(`,
	`%29`, `\)`,
	`%2a`, `\*`,
	`%2b`, `\+`,
	`%2c`, `\,`,
	`%2f`, `\/`,
	`%3a`, `\:`,
	`%3b`, `\;`,
	`%3c`, `\<`,
	`%3d`, `\=`,
	`%3e`, `\>`,
	`%3f`, `\?`,
	`%40`, `\@`,
	`%5b`, `\[`,
	`%5c`, `\\`,
	`%5d`, `\]`,
	`%5e`, `\^`,
	`%60`, "\\`",
	`%7b`, `\{`,
	`%7c`, `\|`,
	`%7d`, `\}`,
	`%7e`, `\~`,
)

// UnbindFS attempts to unbind a string as CPE 2.3 formatted string into a WFN.
func UnbindFS(s string) (WFN, error) {
	r := WFN{}
	if !strings.HasPrefix(s, cpe23Prefix) {
		return r, fmt.Errorf("cpe: malformed CPE formatted string")
	}
	fs := splitFS(s)
	var b strings.Builder
	for i, c := range fs[2:] { // Skip the first two segments, "cpe" and "2.3".
		r.Attr[i].unbindFS(&b, c)
	}
	return r, r.Valid()
}

// UnbindFS undoes the FS binding and assigns it to v.
func (v *Value) unbindFS(b *strings.Builder, s string) {
	if b == nil {
		b = &strings.Builder{}
		b.Grow(len(s))
	}
	switch s {
	case ``:
		v.Kind = ValueUnset
	case `-`:
		v.Kind = ValueNA
	case `*`:
		v.Kind = ValueAny
	default:
		v.Kind = ValueSet
		v.V = unbindFSValue(b, s)
	}
}

// SplitFS splits a string in to unquoted-colon separated segments.
func splitFS(s string) []string {
	var fs []string
	prev, esc := 0, false
	for i, r := range s {
		switch r {
		case '\\':
			esc = true
			continue
		case ':':
			if esc {
				break
			}
			fs = append(fs, s[prev:i])
			prev = i + 1
		default:
		}
		esc = false
	}
	fs = append(fs, s[prev:])
	return fs
}

// UnbindFSValue does what it says on the tin.
//
// Caller provides scratch space for the return construction via the passed
// strings.Builder.
func unbindFSValue(b *strings.Builder, s string) string {
	b.Reset()
	esc := false
	for _, r := range s {
		// We need to re-escape any reserved characters that aren't
		// special.
		switch {
		case r == '\\':
			esc = true
			b.WriteRune('\\')
			continue
		case r == '*' || r == '?':
			fallthrough
		case esc || !reserved(r):
			b.WriteRune(r)
		default:
			b.WriteRune('\\')
			b.WriteRune(r)
		}
		esc = false
	}
	return b.String()
}
