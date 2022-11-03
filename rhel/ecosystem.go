package rhel

import (
	"context"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/rpm"
)

// NewEcosystem provides the set of scanners and coalescer for the rhel ecosystem.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{new(rpm.Scanner)}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{new(DistributionScanner)}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{new(RepositoryScanner)}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return new(Coalescer), nil
		},
	}
}
