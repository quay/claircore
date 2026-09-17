package gobin

import (
	"context"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/language"
)

// NewEcosystem provides the ecosystem for handling go binaries.
func NewEcosystem(_ context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		Name: "gobin",
		PackageScanners: func(context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{Detector{}}, nil
		},
		DistributionScanners: func(context.Context) ([]indexer.DistributionScanner, error) { return nil, nil },
		RepositoryScanners:   func(context.Context) ([]indexer.RepositoryScanner, error) { return nil, nil },
		Coalescer:            language.NewCoalescer,
	}
}
