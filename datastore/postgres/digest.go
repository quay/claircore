package postgres

import (
	"github.com/quay/claircore"
)

// DigestSlice is a helper to avoid excess intermediate allocations when
// handling a slice of Digests.
type digestSlice []claircore.Digest

// MarshalText implements encoding.TextMarshaler.
func (s digestSlice) MarshalText() ([]byte, error) {
	buf := make([]byte, 0, len(s)*75)
	buf = append(buf, '{')
	for i, d := range s {
		if i != 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '"')
		buf = append(buf, d.String()...)
		buf = append(buf, '"')
	}
	buf = append(buf, '}')
	return buf, nil
}
