// Package rpmver implements RPM versioning.
//
// In one place, finally.
package rpmver

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Version is a type for representing NEVRA, NEVR, EVR, and EVRA strings.
//
// The stringified version is normalized into a minimal EVR string, with "name" and
// "architecture" added as available. The [Version.EVR] method provides for
// getting only the EVR string.
type Version struct {
	Name         *string
	Architecture *string
	Epoch        string
	Version      string
	Release      string
}

// Evr writes the formatted EVR string into "b".
func (v *Version) evr(b *strings.Builder) {
	if v.Epoch != "0" {
		b.WriteString(v.Epoch)
		b.WriteByte(':')
	}
	b.WriteString(v.Version)
	b.WriteByte('-')
	b.WriteString(v.Release)
}

// String implements [fmt.Stringer].
func (v *Version) String() string {
	var b strings.Builder
	if v.Name != nil {
		b.WriteString(*v.Name)
		b.WriteByte('-')
	}
	v.evr(&b)
	if v.Architecture != nil {
		b.WriteByte('.')
		b.WriteString(*v.Architecture)
	}

	return b.String()
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (v *Version) UnmarshalText(text []byte) (err error) {
	// This behavior allows for this function to be used as a validator for the
	// passed text. I could go either way on it being desirable. It's not
	// possible to "fill" the pointer from this function.
	if v == nil {
		v = new(Version)
	}
	*v, err = Parse(string(text))
	return err
}

// MarshalText implements [encoding.TextMarshaler].
func (v *Version) MarshalText() ([]byte, error) {
	return []byte(v.String()), nil
}

// IsZero reports true if the receiver is a zero-valued [Version].
func (v *Version) IsZero() bool {
	return v.Name == nil && v.Architecture == nil && v.Epoch == "" && v.Version == "" && v.Release == ""
}

// EVR returns a formatted EVR string.
func (v *Version) EVR() string {
	var b strings.Builder
	v.evr(&b)
	return b.String()
}

// Parse returns a Version for the provided string, or an error if it's
// malformed.
func Parse(v string) (Version, error) {
	ret := Version{
		Epoch: "0",
	}
	switch strings.Count(v, "-") {
	case 0:
		// Missing something: can't be `version-release`.
		return Version{}, fmt.Errorf("rpmver: %s: missing separators", v)
	case 1:
		// `version-release(.arch)`
	default:
		// `some-name-version-release(.arch)`
		i := strings.LastIndexByte(v, '-')
		i = strings.LastIndexByte(v[:i], '-')
		// Can't be -1, there are at least two "-".
		name := v[:i]
		ret.Name = &name
		v = v[i+1:]
	}
	ev, ra, _ := strings.Cut(v, "-")

	ret.Version = ev
	if e, v, ok := strings.Cut(ev, ":"); ok {
		if e != "" {
			ret.Epoch = e
		}
		ret.Version = v
	}

	ret.Release = ra
	if idx := strings.LastIndexByte(ra, '.'); idx != -1 {
		a := ra[idx:]
		if _, ok := architectures[a]; ok {
			arch := a[1:]
			ret.Architecture = &arch
			ret.Release = ra[:idx]
		}
	}

	return ret, nil
}

// Architectures is known architecture strings.
//
// We need to just know these, as there's no good way to know what's an arch tag
// and what's just another version segment.
var architectures = map[string]struct{}{
	".aarch64": {},
	".i686":    {},
	".noarch":  {},
	".ppc64le": {},
	".riscv":   {},
	".s390x":   {},
	".src":     {},
	".x86_64":  {},
}

// Cmp is a mnemonic helper for the comparison result type.
//
// This can't be the return type for [Compare] because all the users expect an
// [int] return.
type cmp int

//go:generate go run golang.org/x/tools/cmd/stringer -type cmp -linecomment -output cmp_string_test.go

const (
	cmpLT cmp = iota - 1 // <
	cmpEQ                // ==
	cmpGT                // >
)

// Compare is a comparison for Versions.
func Compare(a, b *Version) int {
	if cmp := comparePtr(a.Name, b.Name); cmp != 0 {
		return cmp
	}

	if cmp := rpmvercmp(a.Epoch, b.Epoch); cmp != 0 {
		return cmp
	}

	if cmp := rpmvercmp(a.Version, b.Version); cmp != 0 {
		return cmp
	}

	if cmp := rpmvercmp(a.Release, b.Release); cmp != 0 {
		return cmp
	}

	if cmp := comparePtr(a.Architecture, b.Architecture); cmp != 0 {
		return cmp
	}

	return int(cmpEQ)
}

// ComparePtr runs [rpmvercmp] after considering the pointer-ness of the values.
func comparePtr(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return int(cmpEQ)
	case a != nil && b == nil:
		return int(cmpGT)
	case a == nil && b != nil:
		return int(cmpLT)
	default:
	}
	return rpmvercmp(*a, *b)
}

// Rpmvercmp compares RPM version strings.
//
// This is a port of the C version at https://github.com/rpm-software-management/rpm/blob/572844039a04846fe9e030cbacb6336e2240bd6f/rpmio/rpmvercmp.cc
//
//	 1: a is newer than b
//	 0: a and b are the same version
//	-1: b is newer than a
func rpmvercmp(a, b string) int {
	// Easy comparison to see if versions are identical.
	if a == b {
		return 0
	}

	// Loop through each version segment of a and b and compare them.
	for {
		a = strings.TrimLeftFunc(a, rpmSeparatorTrim)
		b = strings.TrimLeftFunc(b, rpmSeparatorTrim)

		// Handle the tilde separator; it sorts before everything else.
		switch {
		case strings.HasPrefix(a, "~") && strings.HasPrefix(b, "~"):
			a = a[1:]
			b = b[1:]
		case strings.HasPrefix(a, "~") && !strings.HasPrefix(b, "~"):
			return -1
		case !strings.HasPrefix(a, "~") && strings.HasPrefix(b, "~"):
			return 1
		}

		// Handle caret separator. Concept is the same as tilde, except that if
		// one of the strings ends (base version), the other is considered as
		// higher version.
		switch {
		case strings.HasPrefix(a, "^") && strings.HasPrefix(b, "^"):
			a = a[1:]
			b = b[1:]
		case a == "" && strings.HasPrefix(b, "^"):
			return -1
		case strings.HasPrefix(a, "^") && b == "":
			return 1
		case strings.HasPrefix(a, "^") && !strings.HasPrefix(b, "^"):
			return -1
		case !strings.HasPrefix(a, "^") && strings.HasPrefix(b, "^"):
			return 1
		}

		// If we ran to the end of either, we are finished with the loop.
		if a == "" || b == "" {
			break
		}

		// Grab first completely alpha or completely numeric segment.
		//
		// Have aSeg and bSeg point to the start of the alpha or numeric segment
		// and walk a and b to end of segment.
		r, _ := utf8.DecodeRuneInString(a)
		isnum := isDigit(r)
		var aSeg, bSeg string
		if isnum {
			aSeg, a = splitFunc(a, isDigit)
			bSeg, b = splitFunc(b, isDigit)
		} else {
			aSeg, a = splitFunc(a, isAlpha)
			bSeg, b = splitFunc(b, isAlpha)
		}

		switch {
		// This cannot happen, as we previously tested to make sure that the
		// first string has a non-null segment.
		case aSeg == "":
			return -1 // Called out as arbitrary in C implementation.

		// Take care of the case where the two version segments are different
		// types: one numeric, the other alpha (i.e. empty). Numeric segments
		// are always newer than alpha segments.
		//
		// XXX See patch #60884 (and details) from bugzilla #50977. (RPM project)
		case bSeg == "" && !isnum:
			return -1
		case bSeg == "" && isnum:
			return 1
		}

		if isnum {
			// This used to be done by converting the digit segments to ints
			// using atoi(). It's changed because long digit segments can
			// overflow an int. This should fix that.

			// Throw away any leading zeros - it's a number, right?
			aSeg = strings.TrimLeft(aSeg, "0")
			bSeg = strings.TrimLeft(bSeg, "0")

			// Whichever number has more digits wins.
			switch {
			case len(aSeg) > len(bSeg):
				return 1
			case len(aSeg) < len(bSeg):
				return -1
			}
		}

		// Strcmp will return which one is greater, even if the two segments are
		// alpha or if they are numeric. Don't return if they are equal because
		// there might be more segments to compare.
		if cmp := strings.Compare(aSeg, bSeg); cmp != 0 {
			return cmp
		}
	}

	switch {
	// This catches the case where all numeric and alpha segments have compared
	// identically but the segment separating characters were different.
	case a == "" && b == "":
		return 0

	// Whichever version still has characters left over wins.
	case a != "" && b == "":
		return 1
	case a == "" && b != "":
		return -1

	// Unreachable:
	case a != "" && b != "":
	}
	panic("unreachable")
}

// RpmSeparatorTrim reports "true" for non-operative separator runes.
func rpmSeparatorTrim(r rune) bool {
	return !isAlnum(r) && r != '~' && r != '^'
}

// SplitFunc splits the string on the index reported by the inverse of IndexFunc.
func splitFunc(s string, f func(rune) bool) (string, string) {
	i := strings.IndexFunc(s, func(r rune) bool { return !f(r) })
	if i == -1 {
		return s, ""
	}
	return s[:i], s[i:]
}

func isAlpha(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func isAlnum(r rune) bool { return isAlpha(r) || isDigit(r) }
