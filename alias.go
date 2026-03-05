package claircore

import (
	"strings"
	"unique"
)

// Alias is an identifier for the same conceptual vulnerability.
// An alias has two parts: the namespace and the name.
//
// The namespace has no format restrictions, but is almost certainly in one of two
// formats:
//   - URI (https://example.com/)
//   - short prefix (EX)
//
// The name has no format restrictions and is only assumed to be unique within
// the namespace.
type Alias struct {
	Space unique.Handle[string]
	Name  string
}

// String implements [fmt.Stringer].
func (a Alias) String() string {
	space := a.Space.Value()

	var b strings.Builder
	b.WriteString(space)
	if strings.Contains(space, "://") { // If URI-ish:
		b.WriteByte('#')
	} else {
		b.WriteByte('-')
	}
	b.WriteString(a.Name)

	return b.String()
}

// Equal reports if two Aliases are the same alias.
func (a Alias) Equal(b Alias) bool {
	return a.Space == b.Space && a.Name == b.Name
}

// Valid reports if the receiver is a valid alias.
//
// A invalid alias is one with a missing or empty Space or Name.
func (a Alias) Valid() bool {
	return a.Space != unique.Handle[string]{} && a.Space.Value() != "" && a.Name != ""
}
