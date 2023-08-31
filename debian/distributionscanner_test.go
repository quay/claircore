package debian

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/quay/zlog"
)

func TestDistributionScanner(t *testing.T) {
	ver := regexp.MustCompile(`^\d+ \(\w+\)$`)
	ctx := zlog.Test(context.Background(), t)
	ents, err := os.ReadDir(`testdata/dist`)
	if err != nil {
		t.Fatal(err)
	}
	dEnts, err := os.ReadDir(`testdata/distroless_dist`)
	if err != nil {
		t.Fatal(err)
	}

	testCase := map[string][]fs.DirEntry{
		"testdata/dist":            ents,
		"testdata/distroless_dist": dEnts,
	}

	for tcDir, tcEnts := range testCase {
		for _, e := range tcEnts {
			t.Run(e.Name(), func(t *testing.T) {
				sys := os.DirFS(filepath.Join(tcDir, e.Name()))
				d, err := findDist(ctx, sys)
				if err != nil {
					t.Error(err)
				}
				if d == nil {
					t.Fatalf("tc: %v | %s does not represent a Debian dist", tcDir, e.Name())
				}
				got, want := d.VersionID, e.Name()
				t.Logf("tc: %v | got: %q, want: %q", tcDir, got, want)
				if got != want {
					t.Fail()
				}
				if !ver.MatchString(d.Version) {
					t.Fatalf("tc: %v | weird version: %q", tcDir, d.Version)
				}
			})
		}
	}
}
