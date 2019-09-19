package defaultscanner

import (
	"context"
	"fmt"
)

// buildResultWithImage retrieves the packages found in the sythesized image layer and
// subsequently queries all individual layers for introducedIn information
func buildResultWithImage(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	for _, scnr := range s.PackageScanners {
		pkgs, err := s.Store.PackagesByLayer(ctx, s.imageLayer.Hash, s.vscnrs)
		if err != nil {
			return Terminal, fmt.Errorf("failed to get packages for image layer %v and scnr %v: %v",
				s.imageLayer.Hash, scnr, err)
		}
		for _, pkg := range pkgs {
			s.report.Packages[pkg.ID] = pkg
		}
	}
	s.logger.Info().Str("state", s.getState().String()).Msg("image report created")

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
