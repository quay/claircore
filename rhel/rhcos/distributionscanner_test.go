package rhcos

import (
	"fmt"
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
			d, err := scanFS(sys)
			if err != nil {
				t.Fatal(err)
			}
			if d == nil || len(d) != 1 {
				t.Fatal("missing distribution")
			}
			// TODO: folder name formatting only works as long as we never want to test for z-stream releases
			if got, want := d[0].Version, fmt.Sprint(n[:1]+"."+n[1:]); got != want {
				t.Errorf("got: %q, want %q", got, want)
			}
		})
	}
}
