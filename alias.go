package claircore

import (
	"encoding/json"
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
		if !strings.HasSuffix(space, "/") { // If not a "directory":
			b.WriteByte('#')
		}
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

type aliasJSON struct {
	Space string `json:"space"`
	Name  string `json:"name"`
}

// MarshalJSON implements [json.Marshaler].
func (a Alias) MarshalJSON() ([]byte, error) {
	var space string
	if a.Space != (unique.Handle[string]{}) {
		space = a.Space.Value()
	}
	return json.Marshal(aliasJSON{
		Space: space,
		Name:  a.Name,
	})
}

// UnmarshalJSON implements [json.Unmarshaler].
func (a *Alias) UnmarshalJSON(data []byte) error {
	var v aliasJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.Space != "" {
		a.Space = unique.Make(v.Space)
	}
	a.Name = v.Name
	return nil
}
