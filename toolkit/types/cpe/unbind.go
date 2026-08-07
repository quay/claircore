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
		var wfn WFN
		return wfn, wfn.UnmarshalFS(s)
	default:
	}
	return WFN{}, fmt.Errorf("cpe: string does not appear to be a bound WFN: %q", s)
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
				if err := r.Attr[attrs[i]].unbindURI(&b, c); err != nil {
					return WFN{}, fmt.Errorf("cpe: %v: %w", attrs[i], err)
				}
			}
			continue
		}
		if err := r.Attr[attrs[i]].unbindURI(&b, c); err != nil {
			return WFN{}, fmt.Errorf("cpe: %v: %w", attrs[i], err)
		}
	}
	return r, r.Valid()
}

func (v *Value) unbindURI(b *strings.Builder, s string) error {
	// From the characters that should be escaped, see
	// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf table 6-1.
	// Need to allow '%' and '~'. The former for escapes and the latter because
	// they're allowed in CPE2.2 URIs.
	const disallow = "!\"#$&'()*+,/:;<=>?@[\\]^`{|}"
	b.Reset()
	switch s {
	case ``:
		v.Kind = ValueAny
	case `-`:
		v.Kind = ValueNA
	default:
		v.Kind = ValueSet
		s = strings.ToLower(s)
		if i := strings.IndexAny(s, disallow); i != -1 {
			return fmt.Errorf("disallowed character %q", s[i])
		}
		valueURI.WriteString(b, s)
		v.V = b.String()
	}
	return nil
}

// ValueURI is a replacer that undoes URI percent encoding and puts legally URI
// encoded characters into formatted-string escaping.
//
// If there are remaining percent encodes, they will be passed through. In
// theory we could normalize these, but I think we'd need to use something a bit
// more heavy-duty, like a [text.Transformer].
var valueURI = strings.NewReplacer(
	`.`, `\.`,
	`-`, `\-`,
	// 2.2 CPEs don't have any special handling for tilde, but 2.3 puts special
	// semantics in the "Edition" component. Those are handled farther up in the
	// call stack, so handle the corner case where there's a tile in another
	// component.
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
	// Do not handle:
	//`:`, `%3a`, // Can't be here anyway, it's used to separate components.
)

// UnbindFS attempts to unbind a string as CPE 2.3 formatted string into a WFN.
//
// Deprecated: Use [WFN.UnmarshalFS].
//
//go:fix inline
func UnbindFS(s string) (wfn WFN, err error) {
	return wfn, wfn.UnmarshalFS(s)
}
