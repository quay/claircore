package bom

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"

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
	const want = 676
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

func TestNestedComponents(t *testing.T) {
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
	    {
	      "type": "library",
	      "bom-ref": "parent",
	      "name": "parent",
	      "purl": "pkg:maven/org.example/parent@1",
	      "components": [
	        {"type": "library", "bom-ref": "child", "name": "child", "purl": "pkg:maven/org.example/child@2"},
	        {"type": "library", "bom-ref": "both", "name": "both", "purl": "pkg:maven/org.example/both@4"},
	        {"type": "library", "bom-ref": "cookie", "name": "js-cookie", "purl": "pkg:npm/js-cookie@3.0.8"}
	      ]
	    },
	    {"type": "library", "bom-ref": "both", "name": "both", "purl": "pkg:maven/org.example/both@4"},
	    {"type": "library", "bom-ref": "holder", "name": "holder", "purl": "pkg:maven/org.example/holder@5"},
	    {
	      "type": "library",
	      "bom-ref": "holder",
	      "name": "holder",
	      "purl": "pkg:maven/org.example/holder@5",
	      "components": [
	        {"type": "library", "bom-ref": "held", "name": "held", "purl": "pkg:maven/org.example/held@6"}
	      ]
	    },
	    {
	      "type": "library",
	      "bom-ref": "mod",
	      "name": "mod",
	      "purl": "pkg:generic/mod@1",
	      "components": [
	        {"type": "library", "bom-ref": "inner", "name": "inner", "purl": "pkg:maven/org.example/inner@3"},
	        {"type": "library", "bom-ref": "pkg:maven/org.example/rich@1", "name": "rich", "purl": "pkg:maven/org.example/rich@1"}
	      ]
	    },
	    {
	      "type": "library",
	      "bom-ref": "pkg:maven/org.example/rich@1",
	      "name": "rich",
	      "purl": "pkg:maven/org.example/rich@1",
	      "hashes": [{"alg": "SHA-256", "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
	      "evidence": {"occurrences": [{"location": "lib/rich-1.jar"}]},
	      "components": [
	        {"type": "library", "bom-ref": "extra", "name": "extra", "purl": "pkg:maven/org.example/extra@9"}
	      ]
	    }
	  ],
	  "dependencies": [{"ref": "app", "dependsOn": ["parent", "both", "mod", "holder", "pkg:maven/org.example/rich@1"]}]
	}`
	seq, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)), cyclonedx.BOMFileFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	wantCPE := cpe.MustUnbind("cpe:/a:redhat:jboss_enterprise_application_platform:8.1").String()
	got := map[string]string{}
	var rich Package
	var sawRich bool
	for p, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		if len(p.CPEs) != 1 || p.CPEs[0].String() != wantCPE {
			t.Fatalf("%s cpes: %v", p.PURL, p.CPEs)
		}
		name := p.PURL.Namespace + ":" + p.PURL.Name
		if _, ok := got[name]; ok {
			t.Fatalf("duplicate %s", name)
		}
		got[name] = p.PURL.Version
		if name == "org.example:rich" {
			rich = p
			sawRich = true
		}
	}
	want := map[string]string{
		"org.example:parent": "1",
		"org.example:child":  "2",
		"org.example:inner":  "3",
		"org.example:both":   "4",
		"org.example:holder": "5",
		"org.example:held":   "6",
		"org.example:rich":   "1",
		"org.example:extra":  "9",
	}
	if len(got) != len(want) {
		t.Fatalf("packages: got %v", got)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s: got %q, want %q", name, got[name], ver)
		}
	}
	if !sawRich {
		t.Fatal("missing rich")
	}
	if rich.Location != "lib/rich-1.jar" {
		t.Fatalf("rich location: got %q", rich.Location)
	}
	sum := hex.EncodeToString(rich.Hashes[HashSHA256])
	if sum != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("rich sha256: got %q", sum)
	}
}

func TestMissingMiddleBOMRef(t *testing.T) {
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
	    {
	      "type": "library",
	      "bom-ref": "parent",
	      "name": "parent",
	      "purl": "pkg:maven/org.example/parent@1",
	      "components": [
	        {
	          "type": "library",
	          "name": "middle",
	          "purl": "pkg:maven/org.example/middle@2",
	          "components": [
	            {"type": "library", "bom-ref": "grandchild", "name": "grandchild", "purl": "pkg:maven/org.example/grandchild@3"}
	          ]
	        },
	        {
	          "type": "library",
	          "name": "gap",
	          "purl": "pkg:generic/gap@1",
	          "components": [
	            {"type": "library", "bom-ref": "inner", "name": "inner", "purl": "pkg:maven/org.example/inner@4"}
	          ]
	        }
	      ]
	    }
	  ],
	  "dependencies": [{"ref": "app", "dependsOn": ["parent"]}]
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
		name := p.PURL.Namespace + ":" + p.PURL.Name
		if _, ok := got[name]; ok {
			t.Fatalf("duplicate %s", name)
		}
		got[name] = p.PURL.Version
	}
	want := map[string]string{
		"org.example:parent":     "1",
		"org.example:middle":     "2",
		"org.example:grandchild": "3",
		"org.example:inner":      "4",
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

func TestNestedFrameworkCPE(t *testing.T) {
	ctx := test.Logging(t)
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app"}},
	  "components": [
	    {
	      "type": "library",
	      "bom-ref": "parent",
	      "name": "parent",
	      "purl": "pkg:maven/a/parent@1",
	      "components": [
	        {"type": "library", "bom-ref": "child", "name": "child", "purl": "pkg:maven/a/child@2"},
	        {"type": "library", "bom-ref": "listed", "name": "listed", "purl": "pkg:maven/a/listed@3"}
	      ]
	    },
	    {"type": "library", "bom-ref": "listed", "name": "listed", "purl": "pkg:maven/a/listed@3"},
	    {
	      "type": "framework",
	      "scope": "excluded",
	      "bom-ref": "fw",
	      "name": "quarkus-bom",
	      "cpe": "cpe:/a:redhat:quarkus:3",
	      "purl": "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@1?type=pom"
	    }
	  ],
	  "dependencies": [
	    {"ref": "app", "dependsOn": ["parent", "fw"]},
	    {"ref": "fw", "provides": ["parent", "listed"]}
	  ]
	}`
	seq, err := LoadCDX(ctx, bytes.NewReader([]byte(doc)), cyclonedx.BOMFileFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	q := cpe.MustUnbind("cpe:/a:redhat:quarkus:3").String()
	got := map[string][]string{}
	for p, err := range seq {
		if err != nil {
			t.Fatal(err)
		}
		name := p.PURL.Namespace + ":" + p.PURL.Name
		if _, ok := got[name]; ok {
			t.Fatalf("duplicate %s", name)
		}
		for _, w := range p.CPEs {
			got[name] = append(got[name], w.String())
		}
		if _, ok := got[name]; !ok {
			got[name] = nil
		}
	}
	if !slices.Equal(got["a:parent"], []string{q}) {
		t.Fatalf("parent: %v", got["a:parent"])
	}
	if !slices.Equal(got["a:child"], []string{q}) {
		t.Fatalf("child: %v", got["a:child"])
	}
	if !slices.Equal(got["a:listed"], []string{q}) {
		t.Fatalf("listed: %v", got["a:listed"])
	}
	if len(got) != 3 {
		t.Fatalf("packages: %v", got)
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
