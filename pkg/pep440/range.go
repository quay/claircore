package pep440

import (
	"fmt"
	"strings"
	"unicode"
)

type op int

const (
	_ op = iota
	opMatch
	opExclusion
	opLTE
	opGTE
	opLT
	opGT
)

type criterion struct {
	Op op
	V  Version
}

func (c *criterion) Match(v *Version) bool {
	switch c.Op {
	case opMatch:
		return c.V.Compare(v) == 0
	case opExclusion:
		return c.V.Compare(v) != 0
	case opLT:
		return c.V.Compare(v) == -1
	case opLTE:
		return c.V.Compare(v) != +1
	case opGT:
		return c.V.Compare(v) == +1
	case opGTE:
		return c.V.Compare(v) != -1
	}
	return false
}

// Range is a set of criteria corresponding to a range of versions.
type Range []criterion

func (r Range) String() string {
	b := strings.Builder{}
	for i, c := range r {
		if i != 0 {
			b.WriteString(", ")
		}
		switch c.Op {
		case opMatch:
			b.WriteString("==")
		case opExclusion:
			b.WriteString("!=")
		case opLTE:
			b.WriteString("<=")
		case opGTE:
			b.WriteString(">=")
		case opLT:
			b.WriteString("<")
		case opGT:
			b.WriteString(">")
		}
		b.WriteString(c.V.String())
	}
	return b.String()
}

// Match reports whether the passed-in Version matches the Range.
func (r Range) Match(v *Version) bool {
	for _, c := range r {
		if !c.Match(v) {
			return false
		}
	}
	return true
}

// AND returns a Range that is the logical AND of the two Ranges.
func (r Range) AND(n Range) Range {
	return append(r, n...)
}

// ParseRange takes a version specifer as described in PEP-440 and turns it into
// a Range, with the following exceptions:
//
// Wildcards are not implemented.
//
// Arbtrary matching (===) is not implemented.
func ParseRange(r string) (Range, error) {
	const op = `~=!<>`
	r = strings.Map(stripSpace, r)

	var ret []criterion
	for _, r := range strings.Split(r, ",") {
		i := strings.LastIndexAny(r, op) + 1
		o := r[:i]
		v, err := Parse(r[i:])
		if err != nil {
			return nil, err
		}
		switch o {
		case "==":
			ret = append(ret, criterion{Op: opMatch, V: v})
		case "!=":
			ret = append(ret, criterion{Op: opExclusion, V: v})
		case "<=":
			ret = append(ret, criterion{Op: opLTE, V: v})
		case ">=":
			ret = append(ret, criterion{Op: opGTE, V: v})
		case "<":
			ret = append(ret, criterion{Op: opLT, V: v})
		case ">":
			ret = append(ret, criterion{Op: opGT, V: v})
		case "~=":
			uv := Version{}
			l := len(v.Release) - 1
			uv.Release = make([]int, l)
			copy(uv.Release, v.Release)
			uv.Release[l-1]++
			uv.Epoch = v.Epoch
			ret = append(ret,
				criterion{Op: opGTE, V: v},
				criterion{Op: opLT, V: uv},
			)

		default:
			return nil, fmt.Errorf("unknown range operator: %q", o)
		}
	}
	return Range(ret), nil
}

func stripSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}
