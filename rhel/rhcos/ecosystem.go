package rhcos

import (
	"context"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/rpm"
)

// NewEcosystem returns a rhcos ecosystem.
func NewEcosystem(_ context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{new(rpm.Scanner)}, nil
		},
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{new(DistributionScanner)}, nil
		},
		RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
			return nil, nil
		},
		FileScanners: func(_ context.Context) ([]indexer.FileScanner, error) {
			return nil, nil
		},
		Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
			return nil, nil
		},
	}
}
