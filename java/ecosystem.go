package java

import (
	"context"

	"github.com/quay/claircore/indexer"
)

// NewEcosystem provides the set of scanners for the java ecosystem.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{&Scanner{}}, nil
		},
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) { return nil, nil },
		RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
			return nil, nil
		},
		Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
			return (*coalescer)(nil), nil
		},
	}
}
