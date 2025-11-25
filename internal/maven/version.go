package maven

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode"
)

// Version implements maven-style versions.
//
// Maven versions have the extremely fun property of being arbitrarily long
// and arbitrarily nested. Put another way, maven versions are trees where
// both adding subtrees and modifying nodes have defined ordering semantics.
//
// The wiki reference is also incorrect -- the comparison function is
// reverse-engineered from actual behavior rather than specified behavior.
//
// See also: https://cwiki.apache.org/confluence/display/MAVENOLD/Versioning
// See also: https://github.com/apache/maven/blob/maven-3.9.x/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java
type Version struct {
	orig string
	c    component
}

// Compare implements the standard "compare" idiom.
//
//   - < == -1
//   - == == 0
//   - > == 1.
func (v *Version) Compare(v2 *Version) int {
	return v.c.Compare(&v2.c)
}

// String implements [fmt.Stringer].
func (v *Version) String() string {
	return v.orig
}

// ParseVersion parses the provided string as a maven version.
func ParseVersion(s string) (*Version, error) {
	v := &Version{
		orig: s,
		c:    component{Kind: kindList},
	}
	var b strings.Builder
	l := &v.c.List
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
	normalize(&v.c.List)
	return v, nil
}

// Component is a node in the tree of a single maven version.
type component struct {
	Kind componentKind
	Str  string
	Int  big.Int // There's no size on a numeric component, because that'd be too easy.
	List []component
}

// ComponentKind indicates the "kind" of a component.
//
// A "null" kind is defined but shouldn't be present in normalized versions.
type componentKind int

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type=componentKind -linecomment

const (
	kindNull   componentKind = iota // null
	kindInt                         // int
	kindString                      // string
	kindList                        // list
)

// String implements [fmt.Stringer].
func (c *component) String() string {
	if c == nil {
		return "<nil>"
	}
	switch c.Kind {
	case kindInt:
		return c.Int.Text(10)
	case kindString:
		return strconv.Quote(c.Str)
	case kindList:
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

// Compare implements the standard "compare" idiom.
//
// The maven version algorithm has the curious property of explicitly
// allowing comparisons to `nil`.
func (c *component) Compare(other *component) int {
	switch {
	case c == nil:
		panic("programmer error: Compare called with nil receiver")
	case c.Kind == kindInt && other == nil:
		other = &component{Kind: kindInt}
		other.Int.SetInt64(0)
		fallthrough
	case c.Kind == kindInt && other.Kind == kindInt:
		return c.Int.Cmp(&other.Int)
	case c.Kind == kindInt && other.Kind == kindList:
		return 1
	case c.Kind == kindInt && other.Kind == kindString:
		return 1
	case c.Kind == kindList && other == nil:
		if len(c.List) == 0 {
			return 0
		}
		for i := range c.List {
			c := c.List[i].Compare(nil)
			if c != 0 {
				return c
			}
		}
		return 0
	case c.Kind == kindList && other.Kind == kindList:
		for i := 0; i < len(c.List) || i < len(other.List); i++ {
			var l, r *component
			if i < len(c.List) {
				l = &c.List[i]
			}
			if i < len(other.List) {
				r = &other.List[i]
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
	case c.Kind == kindList && other.Kind == kindInt:
		return -1
	case c.Kind == kindList && other.Kind == kindString:
		return 1
	case c.Kind == kindString && other == nil:
		other = &component{Kind: kindString, Str: ""}
		fallthrough
	case c.Kind == kindString && other.Kind == kindString:
		return strings.Compare(ordString(c.Str), ordString(other.Str))
	case c.Kind == kindString && other.Kind == kindInt:
		return -1
	case c.Kind == kindString && other.Kind == kindList:
		return -1
	default:
		panic("programmer error: unhandled logic possibility")
	}
}

// AppendInt adds an "int" component to "l" from the contents of "b".
func appendInt(l *[]component, b *strings.Builder) error {
	var v big.Int
	if _, ok := v.SetString(b.String(), 10); !ok {
		return fmt.Errorf("unable to parse number %q", b.String())
	}
	*l = append(*l, component{Kind: kindInt, Int: v})
	b.Reset()
	return nil
}

// AppendInt adds a "string" component to "l" from the contents of "b".
func appendString(l *[]component, b *strings.Builder) error {
	*l = append(*l, component{Kind: kindString, Str: b.String()})
	b.Reset()
	return nil
}

// AppendList adds a "list" component to "l" and returns a pointer to the new component list.
func appendList(l *[]component) *[]component {
	ci := len(*l)
	*l = append(*l, component{Kind: kindList})
	c := &(*l)[ci]
	return &c.List
}

// IsNull reports if the component should be considered null.
func (c *component) isNull() bool {
	return c == nil ||
		c.Kind == kindNull ||
		(c.Kind == kindInt && c.Int.Cmp(big.NewInt(0)) == 0) ||
		(c.Kind == kindString && c.Str == "") ||
		(c.Kind == kindList && len(c.List) == 0)
}

// Normalize does what it says on the tin.
//
// The component list is walked backwards, clipping any effectively-null
// trailing components and normalizing any trailing list components.
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
		} else if c.Kind != kindList {
			break
		}
		normalize(&c.List)
	}
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

// UnknownQualifier is prepended to arbitrary strings in ordString. This value
// means arbitrary qualifiers sort after all known qualifiers, and lexically
// within the set of unknown qualifiers.
const unknownQualifier = 7
