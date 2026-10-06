package java

import (
	"net/url"
	"os"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/java/bom"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestSBOMPackageName(t *testing.T) {
	ctx := test.Logging(t)
	f, err := os.Open("bom/testdata/sbom.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	seq, err := bom.LoadCDX(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for bp, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		if bp.PURL.Namespace != "com.fasterxml.jackson.core" || bp.PURL.Name != "jackson-databind" {
			continue
		}
		var pkg claircore.Package
		if err := bom.PopulatePackage(&pkg, bp, "sbom.cdx.json"); err != nil {
			t.Fatal(err)
		}
		if pkg.Name != "com.fasterxml.jackson.core:jackson-databind" {
			t.Fatalf("name: got %q", pkg.Name)
		}
		if pkg.Version != "2.18.4.redhat-00002" {
			t.Fatalf("version: got %q", pkg.Version)
		}
		if pkg.Kind != types.BinaryPackage {
			t.Fatalf("kind: got %q", pkg.Kind)
		}
		hint, err := url.ParseQuery(pkg.RepositoryHint)
		if err != nil {
			t.Fatal(err)
		}
		if hint.Get("cpe") != bp.CPE.String() {
			t.Fatalf("cpe hint: got %q", hint.Get("cpe"))
		}
		if pkg.PackageDB != "sbom:sbom.cdx.json" {
			t.Fatalf("package db: got %q", pkg.PackageDB)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("jackson-databind not in fixture")
	}
}
