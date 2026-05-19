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
				ir.Files = map[string]map[string]claircore.FileKind{}
			}
			layerHash := l.Hash.String()
			if ir.Files[layerHash] == nil {
				ir.Files[layerHash] = map[string]claircore.FileKind{}
			}
			ir.Files[layerHash][f.Path] = f.Kind
		}
	}
	return ir, nil
}
