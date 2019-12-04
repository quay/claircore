package linux_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/indexer/linux"
	"github.com/quay/claircore/test"
)

func TestCoalescer(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := indexer.NewMockStore(ctrl)
	ps := indexer.NewMockPackageScanner(ctrl)
	ps.EXPECT().Kind().AnyTimes()
	ps.EXPECT().Name().AnyTimes()
	ps.EXPECT().Version().AnyTimes()

	layers, err := test.GenUniqueLayersRemote(1, []string{"http://example.com"})
	if err != nil {
		t.Fatalf("failed to gen unique layers: %v", err)
	}
	packages := test.GenUniquePackages(1)
	dists := test.GenUniqueDistributions(1)
	mockStore.EXPECT().PackagesByLayer(gomock.Any(), gomock.Any(), gomock.Any()).Return(packages, nil)
	mockStore.EXPECT().DistributionsByLayer(gomock.Any(), gomock.Any(), gomock.Any()).Return(dists, nil)

	coalescer := linux.NewCoalescer(mockStore, ps)
	ir, err := coalescer.Coalesce(context.TODO(), layers)
	if err != nil {
		t.Fatalf("coalescing failed: %v", err)
	}

	if _, ok := ir.Packages[0]; !ok {
		t.Fatalf("package not recorded")
	}
	if _, ok := ir.Distributions[0]; !ok {
		t.Fatalf("distribution not recorded")
	}
	if _, ok := ir.DistributionByPackage[0]; !ok {
		t.Fatalf("package was not associated with distribution")
	}
	distID, _ := ir.DistributionByPackage[0]
	if distID != 0 {
		t.Fatalf("expected associated distribution")
	}
	layerHash, _ := ir.PackageIntroduced[0]
	if layerHash != "test-layer-0" {
		t.Fatalf("expected package introduced in hash")
	}
}
