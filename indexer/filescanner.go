package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// FileScanner reports the Files found in a given layer.
type FileScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]claircore.File, error)
}
