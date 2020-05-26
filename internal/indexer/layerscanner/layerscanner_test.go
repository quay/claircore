package layerscanner

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test"
)

// Test_Scan_NoError confirms each scanner is called for each layer presented
// to the layerscanner and no blocking occurs.
func Test_Scan_NoErrors(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctrl := gomock.NewController(t)

	mock_ps := indexer.NewMockPackageScanner(ctrl)
	mock_ds := indexer.NewMockDistributionScanner(ctrl)
	mock_rs := indexer.NewMockRepositoryScanner(ctrl)

	mock_store := indexer.NewMockStore(ctrl)

	layers := test.ServeLayers(ctx, t, 2)

	mock_ps.EXPECT().Scan(gomock.Any(), layers[0]).Return([]*claircore.Package{}, nil)
	mock_ps.EXPECT().Scan(gomock.Any(), layers[1]).Return([]*claircore.Package{}, nil)
	mock_ps.EXPECT().Kind().AnyTimes()
	mock_ps.EXPECT().Name().AnyTimes()
	mock_ps.EXPECT().Version().AnyTimes()

	mock_ds.EXPECT().Scan(gomock.Any(), layers[0]).Return([]*claircore.Distribution{}, nil)
	mock_ds.EXPECT().Scan(gomock.Any(), layers[1]).Return([]*claircore.Distribution{}, nil)
	mock_ds.EXPECT().Kind().AnyTimes()
	mock_ds.EXPECT().Name().AnyTimes()
	mock_ds.EXPECT().Version().AnyTimes()

	mock_rs.EXPECT().Scan(gomock.Any(), layers[0]).Return([]*claircore.Repository{}, nil)
	mock_rs.EXPECT().Scan(gomock.Any(), layers[1]).Return([]*claircore.Repository{}, nil)
	mock_rs.EXPECT().Kind().AnyTimes()
	mock_rs.EXPECT().Name().AnyTimes()
	mock_rs.EXPECT().Version().AnyTimes()

	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[0].Hash, mock_ps).Return(true, nil)
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[1].Hash, mock_ps).Return(true, nil)

	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[0].Hash, mock_ds).Return(true, nil)
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[1].Hash, mock_ds).Return(true, nil)

	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[0].Hash, mock_rs).Return(true, nil)
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[1].Hash, mock_rs).Return(true, nil)

	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[0], mock_ps).Return(nil)
	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[1], mock_ps).Return(nil)

	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[0], mock_rs).Return(nil)
	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[1], mock_rs).Return(nil)

	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[0], mock_ds).Return(nil)
	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[1], mock_ds).Return(nil)

	ecosystem := &indexer.Ecosystem{
		Name: "test-ecosystem",
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{mock_ps}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{mock_ds}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{mock_rs}, nil
		},
	}

	sOpts := &indexer.Opts{
		Store:      mock_store,
		Ecosystems: []*indexer.Ecosystem{ecosystem},
	}

	layerscanner, err := New(ctx, 1, sOpts)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	d, err := claircore.NewDigest("sha256", make([]byte, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}
	if err := layerscanner.Scan(ctx, d, layers); err != nil {
		t.Fatalf("failed to scan test layers: %v", err)
	}
}
