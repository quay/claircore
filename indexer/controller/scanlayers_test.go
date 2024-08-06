package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/wart"
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

	store := indexer_mock.NewMockStore(ctrl)
	pkg := indexer_mock.NewMockPackageScanner(ctrl)
	dist := indexer_mock.NewMockDistributionScanner(ctrl)
	repo := indexer_mock.NewMockRepositoryScanner(ctrl)
	_, descs := test.ServeLayers(t, 2)
	descMatch := make([]*test.LayerMatcher, len(descs))
	for i := range descs {
		descMatch[i] = test.NewLayerMatcher(&descs[i])
	}

	// These type parameters are needed for go1.20.
	setupCalls[*indexer_mock.MockPackageScannerMockRecorder, *indexer_mock.MockStoreMockRecorder](pkg, store, descMatch)
	setupCalls[*indexer_mock.MockDistributionScannerMockRecorder, *indexer_mock.MockStoreMockRecorder](dist, store, descMatch)
	setupCalls[*indexer_mock.MockRepositoryScannerMockRecorder, *indexer_mock.MockStoreMockRecorder](repo, store, descMatch)

	ecosystem := &indexer.Ecosystem{
		Name: "test-ecosystem",
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{pkg}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{dist}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{repo}, nil
		},
	}

	ls := wart.DescriptionsToLayers(descs)
	d, err := claircore.NewDigest("sha256", make([]byte, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}
	m := &claircore.Manifest{
		Hash:   d,
		Layers: ls,
	}

	opts := &indexer.Options{
		Store:      store,
		Ecosystems: []*indexer.Ecosystem{ecosystem},
	}
	c := New(opts)
	c.manifest = m
	c.LayerScanner, err = indexer.NewLayerScanner(ctx, 1, opts)
	if err != nil {
		t.Error(err)
	}

	state, err := scanLayers(ctx, c)
	if err != nil {
		t.Fatalf("failed to scan test layers: %v", err)
	}

	if state != Coalesce {
		t.Errorf("got: %v state, wanted: %v state", state, Coalesce)
	}
}

type scanRecorder interface {
	Kind() *gomock.Call
	Name() *gomock.Call
	Version() *gomock.Call
	// Abuse the fact that we overloaded the "Scan" name. That's finally useful.
	Scan(any, any) *gomock.Call
}

type storeRecorder interface {
	LayerScanned(any, any, any) *gomock.Call
	SetLayerScanned(any, any, any) *gomock.Call
	IndexPackages(any, any, any, any) *gomock.Call
	IndexDistributions(any, any, any, any) *gomock.Call
	IndexRepositories(any, any, any, any) *gomock.Call
}

type mock[R any] interface {
	EXPECT() R
}

// SetupCalls is a helper for doing all the setup for a VersionedScanner mock.
func setupCalls[C scanRecorder, T storeRecorder, Mc mock[C], Mt mock[T]](m Mc, s Mt, ls []*test.LayerMatcher) Mc {
	// In hindsight, this function gains little from being written with
	// generics.
	var retVal any
	var kind string
	scan := m.EXPECT()
	store := s.EXPECT()
	switch t := any(m).(type) {
	case *indexer_mock.MockPackageScanner:
		retVal = []*claircore.Package{}
		kind = "package"
	case *indexer_mock.MockDistributionScanner:
		retVal = []*claircore.Distribution{}
		kind = "distribution"
	case *indexer_mock.MockRepositoryScanner:
		retVal = []*claircore.Repository{}
		kind = "repository"
	default:
		panic(fmt.Sprintf("unreachable: passed %T", t))
	}
	for _, l := range ls {
		scan.Scan(gomock.Any(), l).Return(retVal, nil)
		d := l.DigestMatcher()
		store.LayerScanned(gomock.Any(), d, m).Return(false, nil)
		store.SetLayerScanned(gomock.Any(), d, m).Return(nil)
		switch t := any(m).(type) {
		case *indexer_mock.MockPackageScanner:
			store.IndexPackages(gomock.Any(), gomock.Any(), l, m).Return(nil)
		case *indexer_mock.MockDistributionScanner:
			store.IndexDistributions(gomock.Any(), gomock.Any(), l, m).Return(nil)
		case *indexer_mock.MockRepositoryScanner:
			store.IndexRepositories(gomock.Any(), gomock.Any(), l, m).Return(nil)
		default:
			panic(fmt.Sprintf("unreachable: passed %T", t))
		}
	}
	scan.Kind().MinTimes(1).Return(kind)
	scan.Name().AnyTimes().Return(kind)
	scan.Version().AnyTimes().Return("1")
	return m
}
