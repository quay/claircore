package claircore

import (
	"bytes"
	"strconv"
	"strings"
)

// Version describes a revision of some sort that is ordered correctly within
// its "Kind".
//
// Versions of different kinds do not have any sensible ordering.
type Version struct {
	Kind string
	V    [10]int32
}

// VersionSort returns a function suitable for passing to sort.Slice or
// sort.SliceStable.
func VersionSort(vs []Version) func(int, int) bool {
	return func(i, j int) bool { return vs[i].Compare(&vs[j]) == -1 }
}

// MarshalText implments encoding.TextMarshaler.
func (v *Version) MarshalText() ([]byte, error) {
	if v.Kind == "" {
		return []byte{}, nil
	}
	var buf bytes.Buffer
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer
	buf.WriteString(v.Kind)
	buf.WriteByte(':')
	for i := 0; i < 10; i++ {
		if i != 0 {
			buf.WriteByte('.')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	return buf.Bytes(), nil
}

// UnmarshalText implments encoding.TextUnmarshaler.
func (v *Version) UnmarshalText(text []byte) (err error) {
	idx := bytes.IndexByte(text, ':')
	if idx == -1 {
		return nil
	}
	if v == nil {
		*v = Version{}
	}
	v.Kind = string(text[:idx])
	var n int64
	for i, b := range bytes.Split(text[idx+1:], []byte(".")) {
		n, err = strconv.ParseInt(string(b), 10, 32)
		if err != nil {
			return err
		}
		v.V[i] = int32(n)
	}
	return nil
}

func (v *Version) String() string {
	var buf strings.Builder
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer

	if v.V[0] != 0 {
		buf.Write(strconv.AppendInt(b, int64(v.V[0]), 10))
		buf.WriteByte('!')
	}
	var f, l int
	for i := 1; i < 10; i++ {
		if v.V[i] != 0 {
			if f == 0 {
				f = i
			}
			l = i
		}
	}
	// If we didn't set the offsets in the above loop, bump to make them
	// absolute to the version array.
	if f == 0 {
		f++
	}
	if l == 0 {
		l++
	}
	for i, n := range v.V[f : l+1] {
		if i != 0 {
			buf.WriteByte('.')
		}
		buf.Write(strconv.AppendInt(b, int64(n), 10))
	}

	return buf.String()
}

// Compare returns an integer describing the relationship of two Versions.
//
// The result will be 0 if a==b, -1 if a < b, and +1 if a > b. If the Versions
// are of different kinds, the Kinds will be compared lexographically.
func (v *Version) Compare(x *Version) int {
	if v.Kind != x.Kind {
		return strings.Compare(v.Kind, x.Kind)
	}
	for i := 0; i < 10; i++ {
		if v.V[i] > x.V[i] {
			return 1
		}
		if v.V[i] < x.V[i] {
			return -1
		}
	}
	return 0
}

// Range is a half-open interval of two Versions.
//
// In the usual notation, it is: [Lower, Upper)
type Range struct {
	Lower Version `json:"["`
	Upper Version `json:")"`
}

// Contains reports whether the Version falls within the Range.
func (r *Range) Contains(v *Version) bool {
	if r == nil {
		return false
	}
	// Lower <= v && Upper > v
	return r.Lower.Compare(v) != 1 && r.Upper.Compare(v) == 1
}
