package controller

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// reduce determines which layers should be fetched/scanned and returns these layers
func reduce(ctx context.Context, store indexer.Store, scnrs indexer.VersionedScanners, layers []*claircore.Layer) ([]*claircore.Layer, error) {
	do := []*claircore.Layer{}
	seen := map[string]struct{}{}
	for _, scnr := range scnrs {
		for _, l := range layers {
			ok, err := store.LayerScanned(ctx, l.Hash, scnr)
			if err != nil {
				return nil, err
			}
			if !ok {
				h := l.Hash.String()
				if _, ok := seen[h]; !ok {
					do = append(do, l)
					seen[h] = struct{}{}
				}
			}
		}
	}
	return do, nil
}
