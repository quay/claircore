package ndb

import (
	"context"
	"os"
	"testing"

	"github.com/quay/claircore/rpm/internal/rpm"
)

func TestLoadPackage(t *testing.T) {
	ctx := context.Background()
	pkgf, err := os.Open("testdata/Packages.db")
	if err != nil {
		t.Fatal(err)
	}
	defer pkgf.Close()
	var pkg PackageDB
	if err := pkg.Parse(pkgf); err != nil {
		t.Fatal(err)
	}
	rds, err := pkg.AllHeaders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rd := range rds {
		var h rpm.Header
		if err := h.Parse(ctx, rd); err != nil {
			t.Fatal(err)
		}
		var found bool
		for i := range h.Infos {
			if h.Infos[i].Tag == rpm.TagName {
				found = true
				break
			}
		}
		if !found {
			t.Error(`missing "name" tag`)
		}
	}
}
