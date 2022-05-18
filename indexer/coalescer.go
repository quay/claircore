package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// LayerArifact aggregates the artifacts found within a layer.
type LayerArtifacts struct {
	Hash  claircore.Digest
	Pkgs  []*claircore.Package
	Dist  []*claircore.Distribution // each layer can only have a single distribution
	Repos []*claircore.Repository
}

// Coalescer takes a set of layers and creates coalesced IndexReport.
//
// A coalesced IndexReport should provide only the packages present in the
// final container image once all layers were applied.
type Coalescer interface {
	Coalesce(ctx context.Context, artifacts []*LayerArtifacts) (*claircore.IndexReport, error)
}
