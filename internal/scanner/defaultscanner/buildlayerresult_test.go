package defaultscanner

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func Test_BuildLayerResult_Success(t *testing.T) {
	var tt = []struct {
		// the name of this test
		name          string
		expectedState ScannerState
		// a list of packages our mock will return
		pkgs []*claircore.Package
		// a function to initialize any mocks
		mock func(t *testing.T, pkgs []*claircore.Package) *scanner.MockStore
	}{
		{
			name:          "1 package returned",
			expectedState: ScanFinished,
			pkgs: []*claircore.Package{
				&claircore.Package{
					ID:   1,
					Name: "test-package-1",
				},
			},
			mock: func(t *testing.T, pkgs []*claircore.Package) *scanner.MockStore {
				ctrl := gomock.NewController(t)
				m := scanner.NewMockStore(ctrl)
				m.EXPECT().SetScanReport(gomock.Any(), gomock.Any()).Return(nil)
				m.EXPECT().PackagesByLayer(gomock.Any(), gomock.Any(), gomock.Any()).Return(pkgs, nil)
				return m
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			// get mock
			m := table.mock(t, table.pkgs)

			// create scanner
			opts := &scanner.Opts{
				Store: m,
			}
			s := New(opts)
			s.manifest.Layers = []*claircore.Layer{
				&claircore.Layer{
					Hash: "test-layer-1",
				},
			}

			s.report.Packages = map[int]*claircore.Package{
				table.pkgs[0].ID: table.pkgs[0],
			}

			// call state func
			state, err := buildLayerResult(s, context.Background())

			assert.NoError(t, err)
			assert.Equal(t, table.expectedState, state)
			// confirm we set the introduced id to inform clients of when the particular
			// package was introduced
			assert.Equal(t, s.report.PackageIntroduced[1], "test-layer-1")
		})
	}
}
