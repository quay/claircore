package ruby

import (
	"context"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/language"
)

var scanners = []indexer.PackageScanner{&Scanner{}}

// NewEcosystem provides the set of scanners for the ruby ecosystem.
func NewEcosystem(_ context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners:      func(_ context.Context) ([]indexer.PackageScanner, error) { return scanners, nil },
		DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) { return nil, nil },
		RepositoryScanners:   func(_ context.Context) ([]indexer.RepositoryScanner, error) { return nil, nil },
		Coalescer:            language.NewCoalescer,
	}
}
