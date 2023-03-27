package debian

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/quay/zlog"
)

func TestDistributionScanner(t *testing.T) {
	ver := regexp.MustCompile(`^\d+ \(\w+\)$`)
	ctx := zlog.Test(context.Background(), t)
	ents, err := os.ReadDir(`.testdata/dist`)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Run(e.Name(), func(t *testing.T) {
			sys := os.DirFS(filepath.Join(`.testdata/dist`, e.Name()))
			d, err := findDist(ctx, sys)
			if err != nil {
				t.Error(err)
			}
			got, want := d.VersionID, e.Name()
			t.Logf("got: %q, want: %q", got, want)
			if got != want {
				t.Fail()
			}
			if !ver.MatchString(d.Version) {
				t.Fatalf("weird version: %q", d.Version)
			}
		})
	}
}
