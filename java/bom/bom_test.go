package bom

import (
	"os"
	"slices"
	"testing"

	"github.com/quay/claircore/test"
)

func TestLoad(t *testing.T) {
	ctx := test.Logging(t)
	f, err := os.Open("testdata/sbom.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pkgs, err := Load(ctx, f)
	if err != nil {
		t.Error(err)
	}
	seq := func(yield func(Package) bool) {
		for p, err := range pkgs {
			if err != nil {
				t.Error(err)
				continue
			}
			if !yield(p) {
				return
			}
		}
	}
	out := slices.Collect(seq)
	ct := len(out)
	t.Logf("got: %d", ct)
}
