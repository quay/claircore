package sbom

import (
	"context"
	"github.com/quay/claircore"
	"io"
)

type Encoder interface {
	Encode(ctx context.Context, ir *claircore.IndexReport) (io.Reader, error)
}
