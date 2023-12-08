package sbom

import (
	"context"
	"github.com/quay/claircore"
	"io"
)

// Encoder is an interface to convert a claircore.IndexReport into an io.Reader
// that contains a Software Bill of Materials representation.
type Encoder interface {
	Encode(ctx context.Context, ir *claircore.IndexReport) (io.Reader, error)
}
