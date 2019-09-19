package defaultscanner

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/moby"
)

// fetchLayers fetches all the necessary layers in a manifest.
// if the scanneer has the UseImage configuration a layer representing the stacked layers is created
func fetchLayers(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	s.logger.Info().Str("state", s.getState().String()).Msg("fetching and stacking layers")

	// if UseImage option configured fetch all layers and stack them
	if s.UseImage {
		err := s.Fetcher.Fetch(ctx, s.manifest.Layers)
		if err != nil {
			s.logger.Error().Str("state", s.getState().String()).Msgf("faild to fetch layers: %v", err)
			return Terminal, fmt.Errorf("failed to fetch layers %v", err)
		}

		// create image layer
		stacker := moby.NewStacker()
		imageLayer, err := stacker.Stack(s.manifest.Hash, s.manifest.Layers)
		if err != nil {
			s.logger.Error().Str("state", s.getState().String()).Msgf("failed to stack layers: %v", err)
			return Terminal, fmt.Errorf("failed to stack layer: %v", err)
		}

		// add image layer to scanner
		s.imageLayer = imageLayer

		s.logger.Info().Str("state", s.getState().String()).Msg("fetched and stacked layers")
		return LayerScan, nil
	}

	toFetch := reduce(s.Store, s.vscnrs, s.manifest.Layers)
	err := s.Fetcher.Fetch(ctx, toFetch)
	if err != nil {
		s.logger.Error().Str("state", s.getState().String()).Msgf("faild to fetch layers: %v", err)
		return Terminal, fmt.Errorf("failed to fetch layers %v", err)
	}

	return LayerScan, nil
}

// reduce determines which layers should be fetched and returns these layers
func reduce(store scanner.Store, scnrs scanner.VersionedScanners, layers []*claircore.Layer) []*claircore.Layer {
	toFetch := []*claircore.Layer{}
	for _, scnr := range scnrs {
		for _, l := range layers {
			if ok, _ := store.LayerScanned(l.Hash, scnr); ok {
				continue
			}
			toFetch = append(toFetch, l)
		}
	}
	return toFetch
}
