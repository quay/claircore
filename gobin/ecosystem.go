package gobin

import (
	"context"

	"github.com/quay/claircore/indexer"
)

// NewEcosystem provides the ecosystem for handling go binaries.
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{Detector{}}, nil
		},
		DistributionScanners: func(context.Context) ([]indexer.DistributionScanner, error) { return nil, nil },
		RepositoryScanners:   func(context.Context) ([]indexer.RepositoryScanner, error) { return nil, nil },
		Coalescer:            func(context.Context) (indexer.Coalescer, error) { return &coalescer{}, nil },
	}
}
