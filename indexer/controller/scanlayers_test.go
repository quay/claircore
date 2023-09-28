package controller

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore"
	"github.com/quay/zlog"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
	indexer_mock "github.com/quay/claircore/test/mock/indexer"
)

func TestScanLayers(t *testing.T) {
	ctx := context.Background()
	tt := []struct {
		mock          func(t *testing.T) indexer.Store
		name          string
		expectedState State
	}{
		{
			name:          "Success",
			expectedState: Coalesce,
			mock: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				s := indexer_mock.NewMockStore(ctrl)

				s.EXPECT().LayerScanned(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(true, nil)
				return s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			s := table.mock(t)
			opts := &indexer.Options{
				Store: s,
			}
			scnr := New(opts)
			var err error
			scnr.LayerScanner, err = indexer.NewLayerScanner(ctx, 1, opts)
			if err != nil {
				t.Error(err)
			}

			state, err := scanLayers(ctx, scnr)
			if err != nil {
				t.Error(err)
			}
			if got, want := state, table.expectedState; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}

func TestScanNoErrors(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	ctrl := gomock.NewController(t)

	mock_ps := indexer_mock.NewMockPackageScanner(ctrl)
	mock_ds := indexer_mock.NewMockDistributionScanner(ctrl)
	mock_rs := indexer_mock.NewMockRepositoryScanner(ctrl)
	mock_store := indexer_mock.NewMockStore(ctrl)

	_, layers := test.ServeLayers(t, 2)

	mock_ps.EXPECT().Scan(gomock.Any(), layers[0]).Return([]*claircore.Package{}, nil)
	mock_ps.EXPECT().Scan(gomock.Any(), layers[1]).Return([]*claircore.Package{}, nil)
	mock_ps.EXPECT().Kind().MinTimes(1).Return("package")
	mock_ps.EXPECT().Name().AnyTimes().Return("package")
	mock_ps.EXPECT().Version().AnyTimes().Return("1")
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[0].Hash, mock_ps).Return(false, nil)
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[1].Hash, mock_ps).Return(false, nil)
	mock_store.EXPECT().SetLayerScanned(gomock.Any(), layers[0].Hash, mock_ps).Return(nil)
	mock_store.EXPECT().SetLayerScanned(gomock.Any(), layers[1].Hash, mock_ps).Return(nil)
	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[0], mock_ps).Return(nil)
	mock_store.EXPECT().IndexPackages(gomock.Any(), gomock.Any(), layers[1], mock_ps).Return(nil)

	mock_ds.EXPECT().Scan(gomock.Any(), layers[0]).Return([]*claircore.Distribution{}, nil)
	mock_ds.EXPECT().Scan(gomock.Any(), layers[1]).Return([]*claircore.Distribution{}, nil)
	mock_ds.EXPECT().Kind().MinTimes(1).Return("distribution")
	mock_ds.EXPECT().Name().AnyTimes().Return("distribution")
	mock_ds.EXPECT().Version().AnyTimes().Return("1")
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[0].Hash, mock_ds).Return(false, nil)
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[1].Hash, mock_ds).Return(false, nil)
	mock_store.EXPECT().SetLayerScanned(gomock.Any(), layers[0].Hash, mock_ds).Return(nil)
	mock_store.EXPECT().SetLayerScanned(gomock.Any(), layers[1].Hash, mock_ds).Return(nil)
	mock_store.EXPECT().IndexDistributions(gomock.Any(), gomock.Any(), layers[0], mock_ds).Return(nil)
	mock_store.EXPECT().IndexDistributions(gomock.Any(), gomock.Any(), layers[1], mock_ds).Return(nil)

	mock_rs.EXPECT().Scan(gomock.Any(), layers[0]).Return([]*claircore.Repository{}, nil)
	mock_rs.EXPECT().Scan(gomock.Any(), layers[1]).Return([]*claircore.Repository{}, nil)
	mock_rs.EXPECT().Kind().MinTimes(1).Return("repository")
	mock_rs.EXPECT().Name().AnyTimes().Return("repository")
	mock_rs.EXPECT().Version().AnyTimes().Return("1")
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[0].Hash, mock_rs).Return(false, nil)
	mock_store.EXPECT().LayerScanned(gomock.Any(), layers[1].Hash, mock_rs).Return(false, nil)
	mock_store.EXPECT().SetLayerScanned(gomock.Any(), layers[0].Hash, mock_rs).Return(nil)
	mock_store.EXPECT().SetLayerScanned(gomock.Any(), layers[1].Hash, mock_rs).Return(nil)
	mock_store.EXPECT().IndexRepositories(gomock.Any(), gomock.Any(), layers[0], mock_rs).Return(nil)
	mock_store.EXPECT().IndexRepositories(gomock.Any(), gomock.Any(), layers[1], mock_rs).Return(nil)

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

	sOpts := &indexer.Options{
		Store:      mock_store,
		Ecosystems: []*indexer.Ecosystem{ecosystem},
	}
	d, err := claircore.NewDigest("sha256", make([]byte, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}

	m := &claircore.Manifest{
		Hash:   d,
		Layers: layers,
	}

	scnr := New(sOpts)
	scnr.manifest = m
	scnr.LayerScanner, err = indexer.NewLayerScanner(ctx, 1, sOpts)
	if err != nil {
		t.Error(err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	state, err := scanLayers(ctx, scnr)
	if err != nil {
		t.Fatalf("failed to scan test layers: %v", err)
	}

	if state != Coalesce {
		t.Errorf("got: %v state, wanted: %v state", state, Coalesce)
	}
}
