package updater

import (
	"context"
	"io"

	"github.com/quay/claircore"
)

// Parser is an interface when called with an io.ReadCloser should parse
// the provided contents and return a list of *claircore.Vulnerabilities
type Parser interface {
	// Parse should take an io.ReadCloser, read the contents, parse the contents
	// into a list of claircore.Vulnerability structs and then return
	// the list. Parse should assume contents are uncompressed and ready for parsing.
	Parse(ctx context.Context, contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}
