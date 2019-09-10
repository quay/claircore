// +build test

package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore"
	"github.com/stretchr/testify/assert"
)

// Test_Scanner_ScanError confirms the state machines does the correct
// thing when a stateFunc returns an error.
//
// the scanner is hardcoded to start in checkManifest state. We will have the mock
// fail the call to s.Store.ManifestScanned forcing checkManifest to return an error
// and evaluate our scanner's state afterwards.
func Test_Scanner_ScanError(t *testing.T) {
	var tt = []struct {
		name string
		mock func(t *testing.T) (Store, Fetcher)
	}{
		{
			name: "checkManifest error induced error state",
			mock: func(t *testing.T) (Store, Fetcher) {
				ctrl := gomock.NewController(t)
				store := Newscanner.MockStore(ctrl)
				fetcher := NewMockFetcher(ctrl)

				fetcher.EXPECT().Purge()

				// let call to SetScanReport in checkManifest pass
				store.EXPECT().SetScanReport(gomock.Any()).Return(nil)
				// lets fail call to s.Store.ManifestScanned in check manifest - checkManifest will now return an error and
				// if all is well scanner should hijack SFM flow into entering scanError state
				store.EXPECT().ManifestScanned(gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("expected failure for test"))

				// let the call to SetScanReport in scanError state success. scanErr should return nil. nil from here
				store.EXPECT().SetScanReport(gomock.Any()).Return(nil)

				return store, fetcher
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			store, fetcher := table.mock(t)
			s := NewScanner(&Opts{
				Store:   store,
				Fetcher: fetcher,
			})

			s.Scan(context.Background(), &claircore.Manifest{})

			assert.Equal(t, false, s.result.Success)
			assert.Equal(t, "expected failure for test", s.result.Err)
			assert.Equal(t, ScanError, s.currentState)
		})
	}
}

// Test_Scanner_ScanFinished tests that out state machine does the correct thing
// when it reaches ScanFinished terminal state.
//
// we use the global variable startState to force the state machine into running the scanFinished
// state. we then confirm the ScanReport success bool is set, the appropriate store methods are called,
// and the scanner is in the correct state
func Test_Scanner_ScanFinished(t *testing.T) {
	var tt = []struct {
		name                  string
		expectedState         ScannerState
		expectedResultSuccess bool
		mock                  func(t *testing.T) (Store, Fetcher)
	}{
		{
			name:                  "ScanFinished success",
			expectedState:         ScanFinished,
			expectedResultSuccess: true,
			mock: func(t *testing.T) (Store, Fetcher) {
				ctrl := gomock.NewController(t)
				store := Newscanner.MockStore(ctrl)

				fetcher := NewMockFetcher(ctrl)

				fetcher.EXPECT().Purge()

				store.EXPECT().SetScanFinished(gomock.Any(), gomock.Any()).Return(nil)
				store.EXPECT().SetScanReport(gomock.Any()).Return(nil)

				return store, fetcher
			},
		},
		{
			name:                  "ScanFinished error",
			expectedState:         ScanError,
			expectedResultSuccess: false,
			mock: func(t *testing.T) (Store, Fetcher) {
				ctrl := gomock.NewController(t)
				store := Newscanner.MockStore(ctrl)

				fetcher := NewMockFetcher(ctrl)

				fetcher.EXPECT().Purge()
				// lets cause an error in ScanFinished state when SetScannerList is called. if all goes well
				// we transition to ScanError
				store.EXPECT().SetScanFinished(gomock.Any(), gomock.Any()).Return(fmt.Errorf("expected test failure"))

				// lets allow SetScanReport to pass in ScanError state
				store.EXPECT().SetScanReport(gomock.Any()).Return(nil)

				return store, fetcher
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			store, fetcher := table.mock(t)
			s := NewScanner(&Opts{
				Store:   store,
				Fetcher: fetcher,
			})

			// set global startState for purpose of this test
			startState = scanFinished
			s.Scan(context.Background(), &claircore.Manifest{})

			assert.Equal(t, table.expectedResultSuccess, s.result.Success)
			assert.Equal(t, table.expectedState, s.currentState)
		})
	}
}
