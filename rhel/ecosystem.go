package rhel

import (
	"context"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/rpm"
)

// NewEcosystem provides the set of scanners and coalescers for the rhel ecosystem
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{
				&rpm.Scanner{},
			}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{
				&DistributionScanner{},
			}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{&RepositoryScanner{}}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return NewCoalescer(), nil
		},
	}
}
