package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
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
		mock func(t *testing.T) (indexer.Store, indexer.Fetcher)
		name string
	}{
		{
			name: "CheckManifest",
			mock: func(t *testing.T) (indexer.Store, indexer.Fetcher) {
				ctrl := gomock.NewController(t)
				store := indexer.NewMockStore(ctrl)
				fetcher := indexer.NewMockFetcher(ctrl)

				fetcher.EXPECT().Close()

				// let call to SetIndexReport in checkManifest pass
				store.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)

				// lets fail call to s.Store.ManifestScanned in check manifest - checkManifest will now return an error and
				// if all is well scanner should hijack SFM flow into entering scanError state
				store.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("expected failure for test"))

				// let the call to SetIndexReport in scanError state success. scanErr should return nil. nil from here
				store.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)

				return store, fetcher
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			store, fetcher := table.mock(t)
			c := New(&indexer.Opts{
				Store:   store,
				Fetcher: fetcher,
			})

			c.Index(ctx, &claircore.Manifest{})
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
		mock                  func(t *testing.T) (indexer.Store, indexer.Fetcher)
		name                  string
		expectedState         State
		expectedResultSuccess bool
	}{
		{
			name:                  "Success",
			expectedState:         IndexFinished,
			expectedResultSuccess: true,
			mock: func(t *testing.T) (indexer.Store, indexer.Fetcher) {
				ctrl := gomock.NewController(t)
				store := indexer.NewMockStore(ctrl)

				fetcher := indexer.NewMockFetcher(ctrl)

				fetcher.EXPECT().Close()

				store.EXPECT().SetIndexFinished(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Return(nil)

				return store, fetcher
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			store, fetcher := table.mock(t)
			c := New(&indexer.Opts{
				Store:   store,
				Fetcher: fetcher,
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
