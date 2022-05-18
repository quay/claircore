package indexer

import (
	"context"

	"github.com/quay/claircore"
)

type RepositoryScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]*claircore.Repository, error)
}
