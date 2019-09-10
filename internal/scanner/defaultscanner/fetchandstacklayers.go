package defaultscanner

import (
	"context"
	"fmt"

	"github.com/quay/claircore/moby"
)

// fetchAndStackLayers fetches all the layers in a manifest and then creates a synethic
// stacked layer which simulates the runtime layer of the image. we loosely refer to
// this synethic image as the "image" layer.
func fetchAndStackLayers(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	s.logger.Info().Str("state", s.getState().String()).Msg("fetching and stacking layers")

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
