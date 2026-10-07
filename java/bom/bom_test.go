package bom

import (
	"bytes"
	"os"
	"slices"
	"testing"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestLoad(t *testing.T) {
	ctx := test.Logging(t)
	f, err := os.Open("testdata/sbom.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pkgs, err := LoadCDX(ctx, f)
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
	for _, p := range out {
		if len(p.CPEs) != 1 {
			t.Fatalf("%s: got %d product CPEs", p.PURL, len(p.CPEs))
		}
	}
}

func TestLoadQuarkus(t *testing.T) {
	ctx := test.Logging(t)
	// Fast-jar and uber-jar images carry the same component and provides sets.
	// This is the uber-jar layer document.
	f, err := os.Open("testdata/rhbq-dependency.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	seq, err := LoadCDX(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	wantQuarkus := cpe.MustUnbind("cpe:/a:redhat:quarkus:3.33").String()
	var n, attributed int
	var graphql, unattributed bool
	for p, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		n++
		switch p.PURL.Namespace + ":" + p.PURL.Name {
		case "com.redhat.quarkus.platform:quarkus-bom":
			t.Fatal("framework component was indexed")
		case "org.acme:rhbq-false-positive-reproducer-app":
			t.Fatal("root application was indexed")
		case "io.smallrye:smallrye-graphql":
			if p.PURL.Version != "2.17.0.redhat-00003" {
				continue
			}
			graphql = true
			if len(p.CPEs) != 1 || p.CPEs[0].String() != wantQuarkus {
				t.Fatalf("smallrye-graphql cpes: %v", p.CPEs)
			}
		case "io.quarkus:quarkus-cyclonedx":
			if p.PURL.Version != "3.33.3.redhat-00005" {
				continue
			}
			unattributed = true
			if len(p.CPEs) != 0 {
				t.Fatalf("quarkus-cyclonedx cpes: %v", p.CPEs)
			}
		}
		if len(p.CPEs) > 0 {
			attributed++
		}
	}
	if n != 282 {
		t.Fatalf("packages: got %d, want 282", n)
	}
	if attributed != 198 {
		t.Fatalf("attributed packages: got %d, want 198", attributed)
	}
	if !graphql {
		t.Fatal("smallrye-graphql not in fixture")
	}
	if !unattributed {
		t.Fatal("quarkus-cyclonedx not in fixture")
	}
}

func TestProvidesMultipleProducts(t *testing.T) {
	ctx := test.Logging(t)
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "version": 1,
	  "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app"}},
	  "components": [
	    {"type": "library", "bom-ref": "pkg:maven/a/shared@1", "name": "shared", "purl": "pkg:maven/a/shared@1"},
	    {"type": "library", "bom-ref": "pkg:maven/a/onlyq@1", "name": "onlyq", "purl": "pkg:maven/a/onlyq@1"},
	    {"type": "library", "bom-ref": "pkg:maven/a/none@1", "name": "none", "purl": "pkg:maven/a/none@1"},
	    {
	      "type": "framework",
	      "scope": "excluded",
	      "bom-ref": "fw-q",
	      "name": "quarkus-bom",
	      "cpe": "cpe:/a:redhat:quarkus:3",
	      "purl": "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@1?type=pom",
	      "evidence": {"identity": [
	        {"field": "cpe", "concludedValue": "cpe:/a:redhat:quarkus:3"},
	        {"field": "cpe", "concludedValue": "cpe:/a:redhat:quarkus:3.33"}
	      ]}
	    },
	    {
	      "type": "framework",
	      "scope": "excluded",
	      "bom-ref": "fw-c",
	      "name": "camel-quarkus",
	      "cpe": "cpe:/a:redhat:apache_camel_quarkus:3",
	      "purl": "pkg:maven/com.redhat.camel/camel@1?type=pom"
	    }
	  ],
	  "dependencies": [
	    {"ref": "app", "dependsOn": ["pkg:maven/a/shared@1", "fw-q", "fw-c"]},
	    {"ref": "fw-q", "provides": ["pkg:maven/a/shared@1", "pkg:maven/a/onlyq@1"]},
	    {"ref": "fw-c", "provides": ["pkg:maven/a/shared@1"]}
	  ]
	}`
	seq, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for p, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		name := p.PURL.Namespace + ":" + p.PURL.Name
		for _, w := range p.CPEs {
			got[name] = append(got[name], w.String())
		}
		if _, ok := got[name]; !ok {
			got[name] = nil
		}
	}
	q := cpe.MustUnbind("cpe:/a:redhat:quarkus:3").String()
	q33 := cpe.MustUnbind("cpe:/a:redhat:quarkus:3.33").String()
	c := cpe.MustUnbind("cpe:/a:redhat:apache_camel_quarkus:3").String()
	if !slices.Equal(got["a:shared"], []string{q, q33, c}) {
		t.Fatalf("shared: %v", got["a:shared"])
	}
	if !slices.Equal(got["a:onlyq"], []string{q, q33}) {
		t.Fatalf("onlyq: %v", got["a:onlyq"])
	}
	if cpes := got["a:none"]; len(cpes) != 0 {
		t.Fatalf("none: %v", cpes)
	}
	if _, ok := got["com.redhat.quarkus.platform:quarkus-bom"]; ok {
		t.Fatal("framework was indexed")
	}
	if len(got) != 3 {
		t.Fatalf("packages: %v", got)
	}
}
