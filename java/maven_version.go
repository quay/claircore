package java

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode"
)

// See https://cwiki.apache.org/confluence/display/MAVENOLD/Versioning
//
// Maven versions seem to have the extremely fun property of being arbitrarily long
// and arbitrarily nested. The wiki reference is also incorrect -- the comparison
// function is reverse-engineered from actual behavior rather than specified
// behavior.
//
// See also:
// https://github.com/apache/maven/blob/maven-3.9.x/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java

type mavenVersion struct {
	Orig *string
	C    component
}

type component struct {
	Str  *string
	Int  *big.Int // There's no size on a numeric component, because that'd be too easy.
	List []component
}

const (
	nullComponent = iota
	intComponent
	stringComponent
	listComponent
)

func (c *component) String() string {
	if c == nil {
		return "<nil>"
	}
	switch c.Kind() {
	case intComponent:
		return c.Int.Text(10)
	case stringComponent:
		return strconv.Quote(*c.Str)
	case listComponent:
		var b strings.Builder
		b.WriteByte('[')
		for i := range c.List {
			if i != 0 {
				b.WriteByte(',')
			}
			b.WriteString(c.List[i].String())
		}
		b.WriteByte(']')
		return b.String()
	default:
	}
	return "null"
}
func (c *component) Kind() int {
	switch {
	case c.Int != nil:
		return intComponent
	case c.Str != nil:
		return stringComponent
	case c.List != nil:
		return listComponent
	default:
		return nullComponent
	}
}

func (a *component) Compare(b *component) int {
Again:
	switch {
	case a == nil && b == nil:
		panic("oops")
	case a == nil && b.Kind() == intComponent:
		a = &component{Int: big.NewInt(0)}
		goto Again
	case a == nil && b.Kind() == listComponent:
		a = &component{List: make([]component, 0)}
		goto Again
	case a == nil && b.Kind() == stringComponent:
		a = &component{Str: new(string)}
		goto Again
	case a.Kind() == intComponent && b == nil:
		b = &component{Int: big.NewInt(0)}
		goto Again
	case a.Kind() == intComponent && b.Kind() == intComponent:
		return a.Int.Cmp(b.Int)
	case a.Kind() == intComponent && b.Kind() == listComponent:
		return 1
	case a.Kind() == intComponent && b.Kind() == stringComponent:
		return 1
	case a.Kind() == listComponent && b == nil:
		if len(a.List) == 0 {
			return 0
		}
		for i := range a.List {
			c := a.List[i].Compare(nil)
			if c != 0 {
				return c
			}
		}
		return 0
	case a.Kind() == listComponent && b.Kind() == listComponent:
		for i := 0; i < len(a.List) || i < len(b.List); i++ {
			var l, r *component
			if i < len(a.List) {
				l = &a.List[i]
			}
			if i < len(b.List) {
				r = &b.List[i]
			}
			var res int
			if l == nil {
				if r != nil {
					res = -1 * r.Compare(l)
				}
			} else {
				res = l.Compare(r)
			}
			if res != 0 {
				return res
			}
		}
		return 0
	case a.Kind() == listComponent && b.Kind() == intComponent:
		return -1
	case a.Kind() == listComponent && b.Kind() == stringComponent:
		return 1
	case a.Kind() == stringComponent && b == nil:
		b = &component{Str: new(string)}
		goto Again
	case a.Kind() == stringComponent && b.Kind() == intComponent:
		return -1
	case a.Kind() == stringComponent && b.Kind() == listComponent:
		return -1
	default: // both strings
		return strings.Compare(ordString(*a.Str), ordString(*b.Str))
	}
}

func parseMavenVersion(s string) (*mavenVersion, error) {
	v := &mavenVersion{
		Orig: &s,
	}
	var b strings.Builder
	l := &v.C.List
	isDigit := false
	pos := 0
	for i, r := range s {
		switch {
		case r == '.':
			if i == pos {
				b.WriteByte('0')
			}
			if isDigit {
				if err := appendInt(l, &b); err != nil {
					return nil, err
				}
			} else {
				appendString(l, &b)
			}
			pos = i + 1
		case r == '-':
			if i == pos {
				b.WriteByte('0')
			}
			if isDigit {
				if err := appendInt(l, &b); err != nil {
					return nil, err
				}
			} else {
				appendString(l, &b)
			}
			l = appendList(l)
			pos = i + 1
		case unicode.IsDigit(r):
			if !isDigit && i > pos {
				appendString(l, &b)
				l = appendList(l)
				pos = i
			}
			isDigit = true
			b.WriteRune(r)
		default:
			if isDigit && i > pos {
				if err := appendInt(l, &b); err != nil {
					return nil, err
				}
				l = appendList(l)
				pos = i
			}
			isDigit = false
			b.WriteRune(r)
		}
	}
	if isDigit {
		if err := appendInt(l, &b); err != nil {
			return nil, err
		}
	} else {
		appendString(l, &b)
	}
	normalize(&v.C.List)
	return v, nil
}

func appendInt(l *[]component, b *strings.Builder) error {
	var v big.Int
	if _, ok := v.SetString(b.String(), 10); !ok {
		return fmt.Errorf("unable to parse number %q", b.String())
	}
	*l = append(*l, component{Int: &v})
	b.Reset()
	return nil
}

func appendString(l *[]component, b *strings.Builder) error {
	s := b.String()
	*l = append(*l, component{Str: &s})
	b.Reset()
	return nil
}

func appendList(l *[]component) *[]component {
	ci := len(*l)
	*l = append(*l, component{})
	c := &(*l)[ci]
	return &c.List
}

var zero = big.NewInt(0)

func (c *component) isNull() bool {
	return c == nil ||
		(c.Int != nil && c.Int.Cmp(zero) == 0) ||
		(c.Str != nil && *c.Str == "") ||
		(c.List != nil && len(c.List) == 0)
}

func normalize(cs *[]component) {
	for i := len(*cs) - 1; i >= 0; i-- {
		c := &(*cs)[i]
		if c.isNull() {
			j := i + 1
			if j > len(*cs) {
				*cs = (*cs)[:i]
			} else {
				*cs = append((*cs)[:i], (*cs)[j:]...)
			}
			continue
		} else if c.Kind() != listComponent {
			break
		}
		normalize(&c.List)
	}
}

// Compare is the standard comparision function: < == -1, == == 0, > == 1.
func (v *mavenVersion) Compare(v2 *mavenVersion) int {
	return v.C.Compare(&v2.C)
}

// This is the maven string ordering function.
//
// Takes a string and returns a new string that sorts "properly" lexically.
func ordString(s string) string {
	s = strings.ToLower(s)
	q, ok := qualifiers[s]
	if !ok {
		return fmt.Sprintf("%d-%s", unknownQualifier, s)
	}
	return q
}

// Qualifiers are reverse-engineered from the maven source:
// https://github.com/apache/maven/blob/maven-3.9.x/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L356
var qualifiers = map[string]string{
	"alpha":     "0",
	"a":         "0",
	"beta":      "1",
	"b":         "1",
	"milestone": "2",
	"m":         "2",
	"rc":        "3",
	"cr":        "3",
	"snapshot":  "4",
	"":          "5",
	"ga":        "5",
	"final":     "5",
	"release":   "5",
	"sp":        "6",
}

const unknownQualifier = 7
