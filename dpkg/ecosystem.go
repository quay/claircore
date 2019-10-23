package dpkg

import (
	"context"

	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/osrelease"
)

// NewEcosystem provides the set of scanners and coalescers for the dpkg ecosystem
func NewEcosystem(ctx context.Context) *scanner.Ecosystem {
	return &scanner.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]scanner.PackageScanner, error) {
			return []scanner.PackageScanner{&Scanner{}}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]scanner.DistributionScanner, error) {
			return []scanner.DistributionScanner{&osrelease.Scanner{}}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]scanner.RepositoryScanner, error) {
			return []scanner.RepositoryScanner{}, nil
		},
		Coalescer: func(ctx context.Context, store scanner.Store) (scanner.Coalescer, error) {
			return NewCoalescer(store), nil
		},
	}
}
