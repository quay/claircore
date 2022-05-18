package rpm

import (
	"context"

	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/indexer/linux"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/suse"
)

// NewEcosystem provides the set of scanners and coalescers for the rpm ecosystem
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{&Scanner{}}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{
				&aws.DistributionScanner{},
				&oracle.DistributionScanner{},
				&suse.DistributionScanner{},
				&photon.DistributionScanner{},
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
