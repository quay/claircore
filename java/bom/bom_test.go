package bom

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/quay/claircore/test"
)

func TestFormatFromName(t *testing.T) {
	ok := []struct {
		name string
		want cyclonedx.BOMFileFormat
	}{
		{"sbom.cdx.json", cyclonedx.BOMFileFormatJSON},
		{"dir/sbom.cdx.json.gz", cyclonedx.BOMFileFormatJSON},
		{"META-INF/sbom/app.cdx.xml", cyclonedx.BOMFileFormatXML},
		{"META-INF/sbom/app.cdx.xml.gz", cyclonedx.BOMFileFormatXML},
	}
	for _, tc := range ok {
		got, err := FormatFromName(tc.name)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
	for _, name := range []string{"notes.txt", "sbom.cdx.json.gzip", "app.cdx.xml.gz.bak"} {
		if _, err := FormatFromName(name); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadNoRoot(t *testing.T) {
	ctx := test.Logging(t)
	for _, doc := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{}}`,
	} {
		_, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)), cyclonedx.BOMFileFormatJSON)
		if !errors.Is(err, ErrBadFormat) {
			t.Fatalf("%s: got %v", doc, err)
		}
	}
}

func TestLoad(t *testing.T) {
	ctx := test.Logging(t)
	f, err := os.Open("testdata/sbom.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	format, err := FormatFromName(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadCDX(ctx, f, format)
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
	got := len(out)
	const want = 639
	t.Logf("got: %d, want: %d", got, want)
	if got != want {
		t.Error()
	}
}
