package rhel

import (
	"context"

	"github.com/quay/claircore/indexer"
)

// NewEcosystem provides the set of scanners and coalescer for the rhel ecosystem.
func NewEcosystem(_ context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{PackageScanner{}}, nil
		},
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{new(DistributionScanner)}, nil
		},
		RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{new(RepositoryScanner)}, nil
		},
		Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
			return new(Coalescer), nil
		},
	}
}
