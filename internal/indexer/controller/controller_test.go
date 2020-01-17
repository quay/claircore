package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/test/log"
)

// Test_Controller_IndexError confirms the state machines does the correct
// thing when a stateFunc returns an error.
//
// the controller is hardcoded to start in checkManifest state. We will have the mock
// fail the call to s.Store.ManifestScanned forcing checkManifest to return an error
// and evaluate our scanner's state afterwards.
func Test_Controller_IndexerError(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name string
		mock func(t *testing.T) (indexer.Store, indexer.Fetcher)
	}{
		{
			name: "checkManifest error induced error state",
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
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

// Test_Controller_IndexFinished tests that out state machine does the correct thing
// when it reaches ScanFinished terminal state.
//
// we use the global variable startState to force the state machine into running the scanFinished
// state. we then confirm the IndexReport success bool is set, the appropriate store methods are called,
// and the scanner is in the correct state
func Test_Controller_IndexFinished(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name                  string
		expectedState         State
		expectedResultSuccess bool
		mock                  func(t *testing.T) (indexer.Store, indexer.Fetcher)
	}{
		{
			name:                  "IndexFinished success",
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
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			store, fetcher := table.mock(t)
			// set global startState for purpose of this test
			startState = IndexFinished
			c := New(&indexer.Opts{
				Store:   store,
				Fetcher: fetcher,
			})

			c.Index(ctx, &claircore.Manifest{})
			if !cmp.Equal(table.expectedResultSuccess, c.report.Success) {
				t.Fatal(cmp.Diff(table.expectedResultSuccess, c.report.Success))
			}
			if !cmp.Equal(table.expectedState, c.currentState) {
				t.Fatal(cmp.Diff(table.expectedResultSuccess, c.report.Success))
			}
		})
	}
}
