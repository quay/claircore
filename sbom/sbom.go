package sbom

import (
	"context"
	"io"

	"github.com/quay/claircore"
)

// Encoder is an interface to convert a claircore.IndexReport and writes it to w.
type Encoder interface {
	Encode(ctx context.Context, w io.Writer, ir *claircore.IndexReport) error
}
