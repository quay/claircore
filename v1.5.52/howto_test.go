package docs

import (
	"context"

	"github.com/quay/claircore/indexer"
)

// ANCHOR: example
// HaskellScanner returns a configured PackageScanner.
func haskellScanner() indexer.PackageScanner { return nil }

// HaskellCoalescer returns a configured Coalescer.
func haskellCoalescer() indexer.Coalescer { return nil }

// NewEcosystem provides the set of scanners and coalescers for the haskell
// ecosystem.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{haskellScanner()}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return haskellCoalescer(), nil
		},
	}
}

// ANCHOR_END: example
