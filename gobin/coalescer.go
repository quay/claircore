package gobin

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

type coalescer struct {
}

func (c *coalescer) Coalesce(ctx context.Context, ls []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	return &claircore.IndexReport{
		Environments: map[string][]*claircore.Environment{},
		Packages:     map[string]*claircore.Package{},
		Repositories: map[string]*claircore.Repository{},
	}, nil
}
