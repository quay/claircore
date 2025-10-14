package controller

import (
	"context"
	"log/slog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// reduce determines which layers should be fetched/scanned and returns these layers
func reduce(ctx context.Context, store indexer.Store, scnrs indexer.VersionedScanners, layers []*claircore.Layer) ([]*claircore.Layer, error) {
	do := []*claircore.Layer{}
	for _, l := range layers {
		for _, scnr := range scnrs {
			ok, err := store.LayerScanned(ctx, l.Hash, scnr)
			if err != nil {
				slog.DebugContext(ctx, "unable to lookup layer", "layer", l.Hash, "reason", err)
				return nil, err
			}
			if !ok {
				do = append(do, l)
				break
			}
		}
	}
	return do, nil
}
