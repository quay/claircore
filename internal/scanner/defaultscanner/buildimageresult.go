package defaultscanner

import (
	"context"
	"fmt"
)

func buildImageResult(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	for _, scnr := range s.PackageScanners {
		pkgs, err := s.Store.PackagesByLayer(ctx, s.imageLayer.Hash, s.Vscnrs)
		if err != nil {
			return Terminal, fmt.Errorf("failed to get packages for image layer %v and scnr %v: %v",
				s.imageLayer.Hash, scnr, err)
		}
		for _, pkg := range pkgs {
			s.report.Packages[pkg.ID] = pkg
		}
	}

	s.logger.Info().Str("state", s.getState().String()).Msg("image report created")
	return BuildLayerResult, nil
}
