package bom

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/quay/claircore/test"
)

func TestLoadGzip(t *testing.T) {
	ctx := test.Logging(t)
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "version": 1,
	  "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app", "cpe": "cpe:/a:redhat:quarkus:3"}},
	  "components": [
	    {"type": "library", "bom-ref": "pkg:maven/a/b@1", "name": "b", "purl": "pkg:maven/a/b@1"}
	  ],
	  "dependencies": [
	    {"ref": "app", "dependsOn": ["pkg:maven/a/b@1"]}
	  ]
	}`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	seq, err := LoadCDX(ctx, bytes.NewReader(buf.Bytes()), cyclonedx.BOMFileFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for p, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		n++
		if p.PURL.Namespace+":"+p.PURL.Name != "a:b" {
			t.Fatalf("package: %s:%s", p.PURL.Namespace, p.PURL.Name)
		}
	}
	if n != 1 {
		t.Fatalf("packages: got %d", n)
	}
}

func TestLoadGzipTooLarge(t *testing.T) {
	ctx := test.Logging(t)
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	if _, err := zw.Write(bytes.Repeat([]byte{0}, MaxDocument+1)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCDX(ctx, bytes.NewReader(raw.Bytes()), cyclonedx.BOMFileFormatJSON)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadXML(t *testing.T) {
	ctx := test.Logging(t)
	doc := sampleCDX()
	var plain bytes.Buffer
	if err := cyclonedx.NewBOMEncoder(&plain, cyclonedx.BOMFileFormatXML).Encode(doc); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(plain.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{plain.Bytes(), gz.Bytes()} {
		seq, err := LoadCDX(ctx, bytes.NewReader(body), cyclonedx.BOMFileFormatXML)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		for p, err := range seq {
			if err != nil {
				t.Fatal(err)
			}
			n++
			if p.PURL.Namespace+":"+p.PURL.Name != "a:b" {
				t.Fatalf("package: %s:%s", p.PURL.Namespace, p.PURL.Name)
			}
		}
		if n != 1 {
			t.Fatalf("packages: got %d", n)
		}
	}
}

func sampleCDX() *cyclonedx.BOM {
	doc := cyclonedx.NewBOM()
	doc.Metadata = &cyclonedx.Metadata{
		Component: &cyclonedx.Component{
			Type:   cyclonedx.ComponentTypeApplication,
			Name:   "app",
			BOMRef: "app",
			CPE:    "cpe:/a:redhat:quarkus:3",
		},
	}
	comps := []cyclonedx.Component{{
		Type:       cyclonedx.ComponentTypeLibrary,
		BOMRef:     "pkg:maven/a/b@1",
		Name:       "b",
		PackageURL: "pkg:maven/a/b@1",
	}}
	doc.Components = &comps
	deps := []cyclonedx.Dependency{{
		Ref:          "app",
		Dependencies: &[]string{"pkg:maven/a/b@1"},
	}}
	doc.Dependencies = &deps
	return doc
}
