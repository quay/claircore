package defaultscanner

import (
	"context"
	"fmt"
)

// buildLayerResult is a stateFunc which retrieves all the indexed packages for a layer
// limited by the supplied scanners and populates the result.PackageIntroduced map.
func buildLayerResult(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	for _, layer := range s.manifest.Layers {
		pkgs, err := s.Store.PackagesByLayer(ctx, layer.Hash, s.vscnrs)
		if err != nil {
			s.logger.Error().Str("state", s.getState().String()).Msgf("failed to obtain packages for layer %v: %v", layer.Hash, err)
			return Terminal, fmt.Errorf("failed to obtain packages for layer %v: %v", layer.Hash, err)
		}

		for _, pkg := range pkgs {
			// confirm the package is in the resulting image layer
			_, ok := s.report.Packages[pkg.ID]
			// confirm we haven't already marked the package as introduced
			_, ok1 := s.report.PackageIntroduced[pkg.ID]

			if ok && !ok1 {
				s.report.PackageIntroduced[pkg.ID] = layer.Hash
			}
		}
	}

	s.logger.Info().Str("state", s.getState().String()).Msg("layer result built")
	return ScanFinished, nil
}
