package controller

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
)

// reduce determines which layers should be fetched/scanned and returns these layers
func reduce(ctx context.Context, store scanner.Store, scnrs scanner.VersionedScanners, layers []*claircore.Layer) ([]*claircore.Layer, error) {
	do := []*claircore.Layer{}
	seen := map[string]struct{}{}
	for _, scnr := range scnrs {
		for _, l := range layers {
			ok, err := store.LayerScanned(ctx, l.Hash, scnr)
			if err != nil {
				return nil, err
			}
			if !ok {
				if _, ok := seen[l.Hash]; !ok {
					do = append(do, l)
					seen[l.Hash] = struct{}{}
				}
			}
		}
	}
	return do, nil
}
