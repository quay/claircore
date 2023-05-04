package whiteout

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

type coalescer struct{}

func (c *coalescer) Coalesce(ctx context.Context, layerArtifacts []*indexer.LayerArtifacts) (*claircore.IndexReport, error) {
	ir := &claircore.IndexReport{}
	for _, l := range layerArtifacts {
		for _, f := range l.Files {
			if ir.Files == nil {
				ir.Files = make(map[string]claircore.File)
			}
			ir.Files[l.Hash.String()] = f
		}
	}
	return ir, nil
}
