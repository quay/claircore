package bom

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types/cpe"
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
	for _, p := range out {
		if len(p.CPEs) != 1 {
			t.Fatalf("%s: got %d product CPEs", p.PURL, len(p.CPEs))
		}
	}
}

func TestLoadQuarkus(t *testing.T) {
	ctx := test.Logging(t)
	// Subset of an RHBQ uber-jar document: the root, the excluded framework,
	// one component that framework provides, and one it does not.
	f, err := os.Open("testdata/rhbq-dependency.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	format, err := FormatFromName(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	seq, err := LoadCDX(ctx, f, format)
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
	if n != 2 {
		t.Fatalf("packages: got %d, want 2", n)
	}
	if attributed != 1 {
		t.Fatalf("attributed packages: got %d, want 1", attributed)
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
	seq, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)), cyclonedx.BOMFileFormatJSON)
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

func TestNPMDirectDependency(t *testing.T) {
	ctx := test.Logging(t)
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {
	    "type": "application",
	    "name": "app",
	    "bom-ref": "app",
	    "cpe": "cpe:/a:redhat:jboss_enterprise_application_platform:8.1"
	  }},
	  "components": [
	    {"type": "library", "bom-ref": "pkg:maven/org.example/lib@1", "name": "lib", "purl": "pkg:maven/org.example/lib@1"},
	    {"type": "library", "bom-ref": "pkg:npm/js-cookie@3.0.8", "name": "js-cookie", "purl": "pkg:npm/js-cookie@3.0.8"},
	    {"type": "library", "bom-ref": "pkg:npm/%40angular/core@9.1.0", "name": "@angular/core", "purl": "pkg:npm/%40angular/core@9.1.0"},
	    {"type": "library", "bom-ref": "pkg:generic/foo@1", "name": "foo", "purl": "pkg:generic/foo@1"}
	  ],
	  "dependencies": [{"ref": "app", "dependsOn": [
	    "pkg:maven/org.example/lib@1",
	    "pkg:npm/js-cookie@3.0.8",
	    "pkg:npm/%40angular/core@9.1.0",
	    "pkg:generic/foo@1"
	  ]}]
	}`
	seq, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)), cyclonedx.BOMFileFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	wantCPE := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8.1").String()
	got := map[string]string{}
	for p, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		if len(p.CPEs) != 1 || p.CPEs[0].String() != wantCPE {
			t.Fatalf("%s cpes: %v", p.PURL, p.CPEs)
		}
		var pkg claircore.Package
		if err := PopulatePackage(&pkg, p, "sbom.cdx.json"); err != nil {
			t.Fatal(err)
		}
		got[pkg.Name] = pkg.Version
	}
	want := map[string]string{
		"org.example:lib": "1",
		"js-cookie":       "3.0.8",
		"@angular:core":   "9.1.0",
	}
	if len(got) != len(want) {
		t.Fatalf("packages: got %v", got)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s: got %q, want %q", name, got[name], ver)
		}
	}
}

func TestNoProductCPE(t *testing.T) {
	ctx := test.Logging(t)
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"type": "library", "name": "lib", "bom-ref": "lib"}},
	  "components": [
	    {"type": "library", "bom-ref": "pkg:maven/a/b@1", "name": "b", "purl": "pkg:maven/a/b@1"}
	  ],
	  "dependencies": [{"ref": "lib", "dependsOn": ["pkg:maven/a/b@1"]}]
	}`
	_, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)), cyclonedx.BOMFileFormatJSON)
	if !errors.Is(err, ErrNoProduct) {
		t.Fatalf("got %v", err)
	}

	const bad = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"type": "library", "name": "lib", "bom-ref": "lib", "cpe": "not-a-cpe"}},
	  "components": [
	    {"type": "library", "bom-ref": "pkg:maven/a/b@1", "name": "b", "purl": "pkg:maven/a/b@1"}
	  ],
	  "dependencies": [{"ref": "lib", "dependsOn": ["pkg:maven/a/b@1"]}]
	}`
	_, err = LoadCDX(ctx, bytes.NewReader([]byte(bad)), cyclonedx.BOMFileFormatJSON)
	if err == nil || errors.Is(err, ErrNoProduct) {
		t.Fatalf("got %v", err)
	}
}
