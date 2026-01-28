package sbom

import (
	"context"
	"io"

	"github.com/quay/claircore"
)

// Encoder is an interface to convert a [claircore.IndexReport] into an SBOM document.
type Encoder interface {
	Encode(ctx context.Context, w io.Writer, ir *claircore.IndexReport) error
}

// Decoder is an interface to convert an encoded SBOM into a [claircore.IndexReport].
type Decoder interface {
	Decode(ctx context.Context, r io.Reader) (*claircore.IndexReport, error)
}
