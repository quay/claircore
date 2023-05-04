package whiteout

import (
	"context"

	"github.com/quay/claircore/indexer"
)

// NewEcosystem provides the set of scanners and coalescers for the whiteout ecosystem.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		Name: "whiteout",
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{}, nil
		},
		FileScanners: func(ctx context.Context) ([]indexer.FileScanner, error) {
			return []indexer.FileScanner{&Scanner{}}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return (*coalescer)(nil), nil
		},
	}
}
