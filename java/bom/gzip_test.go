package bom

import (
	"bytes"
	"compress/gzip"
	"testing"

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
	seq, err := LoadCDX(ctx, bytes.NewReader(buf.Bytes()))
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
