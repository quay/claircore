package postgres

import (
	"github.com/jackc/pgtype"

	"github.com/quay/claircore"
)

// DigestSlice is a helper to avoid excess intermediate allocations when
// handling a slice of Digests.
type digestSlice []claircore.Digest

func (s digestSlice) EncodeText(_ *pgtype.ConnInfo, buf []byte) ([]byte, error) {
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
