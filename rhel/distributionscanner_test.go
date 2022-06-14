package rhel

import (
	"io/fs"
	"os"
	"path"
	"testing"
)

func TestDistributionScanner(t *testing.T) {
	sys := os.DirFS(`testdata/releasefiles`)
	ents, err := fs.ReadDir(sys, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Run(e.Name(), func(t *testing.T) {
			n := path.Base(t.Name())
			sys, err := fs.Sub(sys, n)
			if err != nil {
				t.Fatal(err)
			}
			d, err := findDistribution(sys)
			if err != nil {
				t.Fatal(err)
			}
			if d == nil {
				t.Fatal("missing distribution")
			}
			if got, want := d.Version, n; got != want {
				t.Errorf("got: %q, want %q", got, want)
			}
		})
	}
}
