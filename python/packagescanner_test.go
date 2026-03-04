package python_test

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/test"
)

// TestScan runs the python scanner over some layers known to have python
// packages installed.
func TestScanRemote(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	for _, tc := range scanTable {
		t.Run(path.Base(tc.Name), tc.Run(ctx))
	}
}

func TestScanLocal(t *testing.T) {
	t.Parallel()

	type testcase struct {
		Name string
		Want []*claircore.Package
		Path string
	}
	table := []testcase{
		{
			Name: "BadVersion",
			Want: nil,
			Path: "testdata/layer-with-bad-version.tar",
		},
	}

	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := test.Logging(t)
			f, err := os.Open(tt.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			}()
			scanner := &python.Scanner{}
			var l claircore.Layer
			desc := claircore.LayerDescription{
				Digest:    `sha256:` + strings.Repeat(`beef`, 16),
				URI:       `file:///dev/null`,
				MediaType: test.MediaType,
				Headers:   make(map[string][]string),
			}
			if err := l.Init(ctx, &desc, f); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			})

			got, err := scanner.Scan(ctx, &l)
			if err != nil {
				t.Error(err)
			}
			sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
			if !cmp.Equal(got, tt.Want) {
				t.Error(cmp.Diff(got, tt.Want))
			}
		})
	}
}
