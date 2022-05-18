package dpkg

import (
	"context"

	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/indexer/linux"
	"github.com/quay/claircore/ubuntu"
)

// NewEcosystem provides the set of scanners and coalescers for the dpkg ecosystem
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{&Scanner{}}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{
				&debian.DistributionScanner{},
				&ubuntu.DistributionScanner{},
			}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return linux.NewCoalescer(), nil
		},
	}
}
