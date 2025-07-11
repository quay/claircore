package rhcc

import (
	"context"

	"github.com/quay/claircore/indexer"
)

// NewEcosystem returns an rhcc ecosystem.
func NewEcosystem(_ context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{&scanner{}, &detector{}}, nil
		},
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
			return nil, nil
		},
		RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{&reposcanner{}, &repoDetector{}}, nil
		},
		Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
			return &coalescer{}, nil
		},
	}
}
