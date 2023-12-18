package python_test

import (
	"context"
	"encoding/gob"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/test"
)

// TestScan runs the python scanner over some layers known to have python
// packages installed.
func TestScanRemote(t *testing.T) {
	t.Parallel()
	gob.Register(claircore.Package{})
	ctx := context.Background()
	for _, tc := range scanTable {
		// To generate a test fixture, populate the entry in the table below and
		// then run the tests twice.
		f, err := os.Open(filepath.Join(`testdata`, strings.Replace(tc.Hash, ":", "_", 1)+".gob"))
		if err != nil {
			t.Error(err)
		}
		defer f.Close()
		if decErr := gob.NewDecoder(f).Decode(&tc.Want); decErr != nil {
			t.Error(decErr)
		}
		t.Run(path.Base(tc.Name), tc.Run(ctx))
		if t.Failed() && errors.Is(err, fs.ErrNotExist) && tc.Want != nil {
			f, err := os.Create(filepath.Join(`testdata`, strings.Replace(tc.Hash, ":", "_", 1)+".gob"))
			if err != nil {
				t.Error(err)
			}
			defer f.Close()
			if err := gob.NewEncoder(f).Encode(&tc.Want); err != nil {
				t.Error(err)
			}
		}
	}
}

var scanTable = []test.ScannerTestcase{
	{
		Domain:  "docker.io",
		Name:    "library/hylang",
		Hash:    "sha256:a96bd05c55b4e8d8944dbc6567e567dd48442dc65a7e8097fe7510531d4bbb1b",
		Scanner: &python.Scanner{},
	},
	{
		Domain:  "docker.io",
		Name:    "pythonpillow/fedora-30-amd64",
		Hash:    "sha256:cb257051a8e2e33f5216524539bc2bf2e7b29c42d11ceb08caee36e446235c00",
		Scanner: &python.Scanner{},
	},
	{
		Domain:  "docker.io",
		Name:    "pythondiscord/seasonalbot",
		Hash:    "sha256:109a55eba749c02eb6a4533eba12d8aa02a68417ff96886d049798ed5653a156",
		Scanner: &python.Scanner{},
	},
	{
		Domain:  "registry.access.redhat.com",
		Name:    "ubi9/ubi",
		Hash:    "sha256:04dc13843981a3c154bf80963e989347efd76e0b1902f81c1aa2547424209614",
		Scanner: &python.Scanner{},
	},
}

func TestScanLocal(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

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
			ctx := zlog.Test(ctx, t)
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
