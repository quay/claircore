package rpm

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm"
)

// PathSet is a set of paths "owned" by rpm packages in a given layer.
type PathSet = rpm.PathSet

// NewPathSet returns a [PathSet] for the provided layer.
func NewPathSet(ctx context.Context, layer *claircore.Layer) (*PathSet, error) {
	return rpm.NewPathSet(ctx, layer)
}
