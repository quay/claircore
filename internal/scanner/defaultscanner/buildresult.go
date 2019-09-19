package defaultscanner

import (
	"context"
	"fmt"

	"github.com/quay/claircore/internal/scanner"
)

// buildResult retrieves packages found in each layer and uses a Stacker to
// compute the final set of packages
func buildResult(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	stacker := scanner.NewStacker()
	for _, layer := range s.manifest.Layers {
		pkgs, err := s.Store.PackagesByLayer(layer.Hash, s.vscnrs)
		if err != nil {
			return Terminal, fmt.Errorf("failed to get packages for layer %v: %v", layer.Hash, err)
		}
		stacker.Stack(layer, pkgs)
	}
	stackedPkgs, introducedIn := stacker.Result()
	s.report.Packages = stackedPkgs
	s.report.PackageIntroduced = introducedIn

	return ScanFinished, nil
}
