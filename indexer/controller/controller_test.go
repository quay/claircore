package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

// TestControllerIndexError confirms the state machines does the correct thing
// when a stateFunc returns an error.
//
// The controller starts in checkManifest state. We will have the mock fail the
// call to s.Store.ManifestScanned forcing checkManifest to return an error and
// evaluate our scanner's state afterwards.
func TestControllerIndexerError(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		mock func(t *testing.T) (indexer.Store, indexer.FetchArena)
		name string
	}{
		{
			name: "CheckManifest",
			mock: func(t *testing.T) (indexer.Store, indexer.FetchArena) {
				ctrl := gomock.NewController(t)
				store := indexer.NewMockStore(ctrl)
				fa := indexer.NewMockFetchArena(ctrl)
				realizer := indexer.NewMockRealizer(ctrl)
				realizer.EXPECT().Close()
				fa.EXPECT().Realizer(gomock.Any()).Return(realizer)

				// let call to SetIndexReport in checkManifest pass
				store.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)

				// lets fail call to s.Store.ManifestScanned in check manifest - checkManifest will now return an error and
				// if all is well scanner should hijack SFM flow into entering scanError state
				store.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("expected failure for test"))

				return store, fa
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			store, fa := table.mock(t)
			c := New(&indexer.Opts{
				Store:      store,
				FetchArena: fa,
			})

			_, err := c.Index(ctx, &claircore.Manifest{})
			if errors.Is(err, nil) {
				t.Error("expected nil error")
			}
			if !cmp.Equal(false, c.report.Success) {
				t.Fatal(cmp.Diff(false, c.report.Success))
			}
			if c.report.Err == "" {
				t.Fatalf("expected Err string on index report")
			}
			if !cmp.Equal(IndexError.String(), c.report.State) {
				t.Fatal(cmp.Diff(IndexError.String(), c.report.State))
			}
		})
	}
}

// TestControllerIndexFinished tests that out state machine does the correct
// thing when it reaches ScanFinished terminal state.
func TestControllerIndexFinished(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tt := []struct {
		mock                  func(t *testing.T) (indexer.Store, indexer.FetchArena)
		name                  string
		expectedState         State
		expectedResultSuccess bool
	}{
		{
			name:                  "Success",
			expectedState:         IndexFinished,
			expectedResultSuccess: true,
			mock: func(t *testing.T) (indexer.Store, indexer.FetchArena) {
				ctrl := gomock.NewController(t)
				store := indexer.NewMockStore(ctrl)
				fa := indexer.NewMockFetchArena(ctrl)
				realizer := indexer.NewMockRealizer(ctrl)

				realizer.EXPECT().Close()
				fa.EXPECT().Realizer(gomock.Any()).Return(realizer)

				store.EXPECT().SetIndexFinished(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)

				return store, fa
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			store, fa := table.mock(t)
			c := New(&indexer.Opts{
				Store:      store,
				FetchArena: fa,
			})
			c.setState(IndexFinished)

			c.Index(ctx, &claircore.Manifest{})
			if got, want := c.report.Success, table.expectedResultSuccess; !cmp.Equal(got, want) {
				t.Fatal(cmp.Diff(got, want))
			}
			if got, want := c.currentState, table.expectedState; !cmp.Equal(got, want) {
				t.Fatal(cmp.Diff(got, want))
			}
		})
	}
}
