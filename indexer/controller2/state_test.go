package controller

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

func TestStates(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	fakeManifest := claircore.Manifest{
		Hash: test.RandomSHA256Digest(t),
		Layers: []*claircore.Layer{
			{
				Hash: test.RandomSHA256Digest(t),
			},
		},
	}
	indexers := test.GenUniquePackageScanners(4)
	aCtx := gomock.AssignableToTypeOf(reflect.TypeOf((*context.Context)(nil)).Elem())
	aDigest := gomock.AssignableToTypeOf(reflect.TypeOf((*claircore.Digest)(nil)).Elem())

	indexReportErr := errors.New("(store).IndexReport")
	manifestScannedErr := errors.New("(store).ManifestScanned")
	persistManifestErr := errors.New("(store).PersistManifest")
	runTests(ctx, t, "CheckManifest", _CheckManifest,
		stateTestcase{
			Name: "Seen",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(0)).
					Return(true, nil)
				m.EXPECT().
					IndexReport(aCtx, fakeManifest.Hash).
					Return(&claircore.IndexReport{}, true, nil)
				s.Store = m
			},
			Check: func(t *testing.T, s *indexState) {
				if s.Err != nil {
					t.Error(s.Err)
				}
			},
		},
		stateTestcase{
			Name: "PartialSeen",
			Want: _FetchLayers,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				call := m.EXPECT().
					ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(len(indexers))).
					Return(false, nil)
				for i := 0; i < len(indexers); i++ {
					call = m.EXPECT().
						ManifestScanned(aCtx, fakeManifest.Hash, indexers[i:i+1]).
						Return(true, nil).
						After(call)
				}
				m.EXPECT().
					PersistManifest(aCtx, fakeManifest).
					Return(nil)

				s.Manifest = &fakeManifest
				s.Indexers = indexers
				s.Store = m
			},
			Check: func(t *testing.T, s *indexState) {
				if s.Err != nil {
					t.Error(s.Err)
				}
			},
		},
		stateTestcase{
			Name: "Unseen",
			Want: _FetchLayers,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					ManifestScanned(aCtx, aDigest, gomock.Any()).
					Return(false, nil)
				m.EXPECT().
					PersistManifest(aCtx, gomock.Any()).
					Return(nil)
				s.Store = m
			},
		},
		stateTestcase{
			Name: "Disappeared",
			Want: _SeenManifest,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(0)).
					Return(true, nil)
				m.EXPECT().
					IndexReport(aCtx, fakeManifest.Hash).
					Return(nil, false, nil)
				s.Store = m
			},
			Check: func(t *testing.T, s *indexState) {
				if s.Err == nil {
					t.Error("wanted non-nil error")
					return
				}
				got, want := s.Err, manifestDisappeared(fakeManifest.Hash)
				t.Logf("got: %#q, want: %#q", got, want)
				if !errors.Is(got, want) {
					t.Fail()
				}
			},
		},
		stateTestcase{
			Name: "IndexReportError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(0)).
					Return(true, nil)
				m.EXPECT().
					IndexReport(aCtx, fakeManifest.Hash).
					Return(nil, false, indexReportErr)
				s.Store = m
			},
			Check: checkErr(indexReportErr),
		},
		stateTestcase{
			Name: "ManifestScannedError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(0)).
					Return(false, manifestScannedErr)

				s.Manifest = &fakeManifest
				s.Store = m
			},
			Check: checkErr(manifestScannedErr),
		},
		stateTestcase{
			Name: "ManifestScannedIndividualError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				gomock.InOrder(
					m.EXPECT().
						ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(4)).
						Return(false, nil),
					m.EXPECT().
						ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(1)).
						Return(false, nil),
					m.EXPECT().
						ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(1)).
						Return(true, nil),
					m.EXPECT().
						ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(1)).
						Return(true, nil),
					m.EXPECT().
						ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(1)).
						Return(false, manifestScannedErr),
				)

				s.Manifest = &fakeManifest
				s.Store = m
				s.Indexers = indexers
			},
			Check: checkErr(manifestScannedErr),
		},
		stateTestcase{
			Name: "PersistManifestError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					ManifestScanned(aCtx, fakeManifest.Hash, gomock.Len(0)).
					Return(false, nil)
				m.EXPECT().
					PersistManifest(aCtx, gomock.Any()).
					Return(persistManifestErr)

				s.Manifest = &fakeManifest
				s.Store = m
			},
			Check: checkErr(persistManifestErr),
		},
	)

	realizeErr := errors.New("(realizer).Realize")
	storeLayerScannedErr := errors.New("(store).LayerScanned")
	runTests(ctx, t, "FetchLayers", _FetchLayers,
		stateTestcase{
			Name: "Success",
			Want: _IndexLayers,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				r := indexer.NewMockRealizer(ctl)
				r.EXPECT().
					Realize(aCtx, gomock.Any()).
					Times(1).
					Return(nil)

				s.Manifest = &fakeManifest
				s.Realizer = r
			},
		},
		stateTestcase{
			Name: "RealizeFailure",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				r := indexer.NewMockRealizer(ctl)
				r.EXPECT().
					Realize(aCtx, gomock.Any()).
					Times(1).
					Return(realizeErr)

				s.Manifest = &fakeManifest
				s.Realizer = r
			},
			Check: checkErr(realizeErr),
		},
		stateTestcase{
			Name: "StoreFailure",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				r := indexer.NewMockRealizer(ctl)
				r.EXPECT().
					Realize(aCtx, gomock.Any()).
					Times(0).
					Return(nil)
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					LayerScanned(aCtx, fakeManifest.Layers[0].Hash, gomock.Any()).
					Return(false, storeLayerScannedErr)

				s.Manifest = &fakeManifest
				s.Realizer = r
				s.Store = m
				s.Indexers = indexers
			},
			Check: checkErr(storeLayerScannedErr),
		},
		stateTestcase{
			Name: "NovelStore",
			Want: _IndexLayers,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				r := indexer.NewMockRealizer(ctl)
				r.EXPECT().
					Realize(aCtx, gomock.Len(1)).
					Times(1).
					Return(nil)
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					LayerScanned(aCtx, fakeManifest.Layers[0].Hash, gomock.Any()).
					Return(false, nil)

				s.Manifest = &fakeManifest
				s.Realizer = r
				s.Store = m
				s.Indexers = indexers
			},
			// Check: checkErr(storeLayerScannedErr),
		},
	)

	layerScanErr := errors.New("(layerscanner).Scan")
	runTests(ctx, t, "ScanLayers", _IndexLayers,
		stateTestcase{
			Name: "Success",
			Want: _Coalesce,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &claircore.Manifest{}
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					LayerScanned(aCtx, gomock.Any(), gomock.Any()).
					AnyTimes().
					Return(true, nil)
				ls := indexer.NewMockLayerScanner(ctl)
				ls.EXPECT().
					Scan(aCtx, aDigest, gomock.Any()).
					Times(1).
					Return(nil)
				s.Store = m
				s.LayerIndexer = ls
			},
		},
		stateTestcase{
			Name: "Failure",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					LayerScanned(aCtx, gomock.Any(), gomock.Any()).
					AnyTimes().
					Return(true, nil)
				ls := indexer.NewMockLayerScanner(ctl)
				ls.EXPECT().
					Scan(aCtx, fakeManifest.Hash, gomock.Len(1)).
					Times(1).
					Return(layerScanErr)

				s.Manifest = &fakeManifest
				s.Store = m
				s.LayerIndexer = ls
			},
			Check: checkErr(layerScanErr),
		},
	)

	ecosystemPackageErr := errors.New("(ecosystem).PackageScanners")
	ecosystemDistributionErr := errors.New("(ecosystem).DistributionScanners")
	ecosystemRepositoryErr := errors.New("(ecosystem).RepositoryScanners")
	storePackagesErr := errors.New("(store).PackagesByLayer")
	storeDistributionsErr := errors.New("(store).DistributionsByLayer")
	storeRepositoriesErr := errors.New("(store).RepositoriesByLayer")
	coalescerErr := errors.New("(ecosystem).Coalescer")
	coalesceErr := errors.New("(coalescer).Coalesce")
	runTests(ctx, t, "Coalesce", _Coalesce,
		stateTestcase{
			Name: "SuccessNoEcosystems",
			Want: _IndexManifest,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
			},
		},
		stateTestcase{
			Name: "Success",
			Want: _IndexManifest,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				co := indexer.NewMockCoalescer(ctl)
				co.EXPECT().
					Coalesce(aCtx, gomock.Any()).
					Return(new(claircore.IndexReport), nil)
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					PackagesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					DistributionsByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					RepositoriesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Store = m
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return co, nil
					},
				}}
			},
		},
		stateTestcase{
			Name: "PackageScannerFail",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, ecosystemPackageErr
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, nil
					},
				}}
			},
			Check: checkErr(ecosystemPackageErr),
		},
		stateTestcase{
			Name: "DistributionScannerFail",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, ecosystemDistributionErr
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, nil
					},
				}}
			},
			Check: checkErr(ecosystemDistributionErr),
		},
		stateTestcase{
			Name: "RepositoryScannerFail",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, ecosystemRepositoryErr
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, nil
					},
				}}
			},
			Check: checkErr(ecosystemRepositoryErr),
		},
		stateTestcase{
			Name: "StorePackagesError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					PackagesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, storePackagesErr)
				m.EXPECT().
					DistributionsByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(0).
					Return(nil, nil)
				m.EXPECT().
					RepositoriesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(0).
					Return(nil, nil)
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Store = m
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, nil
					},
				}}
			},
			Check: checkErr(storePackagesErr),
		},
		stateTestcase{
			Name: "StoreDistributionsError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					PackagesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					DistributionsByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, storeDistributionsErr)
				m.EXPECT().
					RepositoriesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(0).
					Return(nil, nil)
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Store = m
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, nil
					},
				}}
			},
			Check: checkErr(storeDistributionsErr),
		},
		stateTestcase{
			Name: "StoreRepositoriesError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					PackagesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					DistributionsByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					RepositoriesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, storeRepositoriesErr)
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Store = m
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, nil
					},
				}}
			},
			Check: checkErr(storeRepositoriesErr),
		},
		stateTestcase{
			Name: "CoalescerError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					PackagesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					DistributionsByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					RepositoriesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Store = m
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return nil, coalescerErr
					},
				}}
			},
			Check: checkErr(coalescerErr),
		},
		stateTestcase{
			Name: "CoalesceError",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					PackagesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					DistributionsByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				m.EXPECT().
					RepositoriesByLayer(aCtx, fakeManifest.Layers[0].Hash, gomock.Len(0)).
					Times(1).
					Return(nil, nil)
				co := indexer.NewMockCoalescer(ctl)
				co.EXPECT().
					Coalesce(aCtx, gomock.Any()).
					Times(1).
					Return(nil, coalesceErr)
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				s.Store = m
				s.Ecosystems = []indexer.Ecosystem{{
					Name: "test",
					PackageScanners: func(_ context.Context) ([]indexer.PackageScanner, error) {
						return nil, nil
					},
					DistributionScanners: func(_ context.Context) ([]indexer.DistributionScanner, error) {
						return nil, nil
					},
					RepositoryScanners: func(_ context.Context) ([]indexer.RepositoryScanner, error) {
						return nil, nil
					},
					Coalescer: func(_ context.Context) (indexer.Coalescer, error) {
						return co, nil
					},
				}}
			},
			Check: checkErr(coalesceErr),
		},
	)

	runTests(ctx, t, "IndexManifest", _IndexManifest,
		stateTestcase{
			Name: "Success",
			Want: _IndexFinished,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					IndexManifest(aCtx, gomock.Any()).
					Return(nil)
				s.Store = m
			},
		},
		stateTestcase{
			Name: "Failure",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					IndexManifest(aCtx, gomock.Any()).
					Return(errors.New("failure"))
				s.Store = m
			},
		},
	)

	indexFinishedErr := errors.New("(store).SetIndexedFinished")
	runTests(ctx, t, "IndexFinished", _IndexFinished,
		stateTestcase{
			Name: "Success",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &fakeManifest
				s.Out = &claircore.IndexReport{}
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					SetIndexFinished(aCtx, s.Out, gomock.Any()).
					Return(nil)
				s.Store = m
			},
		},
		stateTestcase{
			Name: "Failure",
			Want: nil,
			Setup: func(t *testing.T, ctl *gomock.Controller, s *indexState) {
				s.Manifest = &claircore.Manifest{}
				s.Out = &claircore.IndexReport{}
				m := indexer.NewMockStore(ctl)
				m.EXPECT().
					SetIndexFinished(aCtx, s.Out, gomock.Any()).
					Return(indexFinishedErr)
				s.Store = m
			},
			Check: checkErr(indexFinishedErr),
		},
	)
}

func runTests(ctx context.Context, t *testing.T, name string, start stateFn, tcs ...stateTestcase) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()
		if len(tcs) == 0 {
			t.Skip("no testcases provided")
		}
		ctx := zlog.Test(ctx, t)
		for _, tc := range tcs {
			t.Run(tc.Name, tc.Run(ctx, start))
		}
	})
}

type stateTestcase struct {
	Want  stateFn
	Setup func(*testing.T, *gomock.Controller, *indexState)
	Check func(*testing.T, *indexState)
	Name  string
}

func (tc stateTestcase) Run(ctx context.Context, fn stateFn) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := zlog.Test(ctx, t)
		var s indexState
		tc.Setup(t, gomock.NewController(t), &s)
		if t.Failed() {
			t.FailNow()
		}
		next := fn(ctx, &s)
		got, want := reflect.ValueOf(next).Pointer(), reflect.ValueOf(tc.Want).Pointer()
		t.Logf("got: 0x%x (%q), want: 0x%x (%q)",
			got, runtime.FuncForPC(got).Name(), want, runtime.FuncForPC(want).Name())
		if got != want {
			t.Fail()
		}
		if tc.Check != nil {
			tc.Check(t, &s)
		}
	}
}

func checkErr(want error) func(*testing.T, *indexState) {
	return func(t *testing.T, s *indexState) {
		got := s.Err
		if got == nil {
			t.Error("wanted non-nil error")
			return
		}
		t.Logf("got: %v, want: %v", got, want)
		if !errors.Is(got, want) {
			t.Fail()
		}
	}
}

func TestRun(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	ctl := gomock.NewController(t)
	m := indexer.NewMockStore(ctl)
	m.EXPECT().
		ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(false, nil)
	m.EXPECT().
		PersistManifest(gomock.Any(), gomock.Any()).
		Return(nil)
	m.EXPECT().
		IndexManifest(gomock.Any(), gomock.Any()).
		Return(nil)
	m.EXPECT().
		SetIndexFinished(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil)
	m.EXPECT().
		SetIndexReport(gomock.Any(), gomock.Any()).
		Times(6).
		Return(nil)
	r := indexer.NewMockRealizer(ctl)
	r.EXPECT().
		Realize(gomock.Any(), gomock.Any()).
		Return(nil)
	li := indexer.NewMockLayerScanner(ctl)
	li.EXPECT().
		Scan(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil)

	s := indexState{
		Store:        m,
		Realizer:     r,
		LayerIndexer: li,
		Manifest: &claircore.Manifest{
			Hash: test.RandomSHA256Digest(t),
			Layers: []*claircore.Layer{
				{
					Hash: test.RandomSHA256Digest(t),
				},
			},
		},
	}
	s.Out = newIndexReport(s.Manifest.Hash)

	if err := s.run(ctx); err != nil {
		t.Error(err)
	}
}
