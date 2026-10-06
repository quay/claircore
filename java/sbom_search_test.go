package java_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/java"
	"github.com/quay/claircore/test"
)

// TestEmbeddedSBOMNotReplacedByMavenSearch checks that a configured search
// client is used for a filename guess and is not used for an embedded
// CycloneDX component, even when the search would return a hit.
func TestEmbeddedSBOMNotReplacedByMavenSearch(t *testing.T) {
	ctx := test.Logging(t)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"docs":[{"id":"central:replaced:9.9.9","g":"central","a":"replaced","v":"9.9.9"}]}}`))
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	writeSearchZip(t, filepath.Join(root, "carrier-1.0.jar"), map[string]string{
		"META-INF/sbom/dependency.cdx.json": string(searchCDX(t)),
	})
	writeSearchZip(t, filepath.Join(root, "plain-1.0.jar"), map[string]string{
		"placeholder.txt": "plain",
	})

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&java.ScannerConfig{API: srv.URL}); err != nil {
		t.Fatal(err)
	}
	scanner := new(java.Scanner)
	if err := scanner.Configure(ctx, json.NewDecoder(&buf).Decode, srv.Client()); err != nil {
		t.Fatal(err)
	}

	var l claircore.Layer
	desc := claircore.LayerDescription{
		Digest:    test.RandomSHA256Digest(t).String(),
		URI:       "file://" + root,
		MediaType: "application/vnd.claircore.filesystem",
		Headers:   map[string][]string{},
	}
	if err := l.Init(ctx, &desc, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	pkgs, err := scanner.Scan(ctx, &l)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("maven searches: got %d, want 1", calls)
	}

	var sawSBOM, sawSearch bool
	for _, pkg := range pkgs {
		switch {
		case pkg.Name == "org.example:embedded":
			sawSBOM = true
			if pkg.Version != "1.0" {
				t.Errorf("embedded version: got %q, want 1.0", pkg.Version)
			}
			if !strings.HasPrefix(pkg.PackageDB, "sbom:") {
				t.Errorf("embedded PackageDB: got %q, want sbom: prefix", pkg.PackageDB)
			}
		case pkg.Name == "central:replaced" && pkg.Version == "9.9.9":
			sawSearch = true
		}
	}
	if !sawSBOM {
		t.Errorf("missing embedded component; packages: %+v", pkgs)
	}
	if !sawSearch {
		t.Errorf("filename jar was not resolved by search; packages: %+v", pkgs)
	}
}

func searchCDX(t *testing.T) []byte {
	t.Helper()
	components := []cyclonedx.Component{{
		BOMRef:     "pkg:maven/org.example/embedded@1.0",
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       "embedded",
		Version:    "1.0",
		PackageURL: "pkg:maven/org.example/embedded@1.0",
	}}
	dependsOn := []string{"pkg:maven/org.example/embedded@1.0"}
	dependencies := []cyclonedx.Dependency{{
		Ref:          "app",
		Dependencies: &dependsOn,
	}}
	bom := &cyclonedx.BOM{
		BOMFormat:   cyclonedx.BOMFormat,
		SpecVersion: cyclonedx.SpecVersion1_6,
		Version:     1,
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Type:   cyclonedx.ComponentTypeApplication,
				BOMRef: "app",
				Name:   "app",
				CPE:    "cpe:/a:redhat:jboss_enterprise_application_platform:8.1",
			},
		},
		Components:   &components,
		Dependencies: &dependencies,
	}
	var buf bytes.Buffer
	if err := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON).Encode(bom); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeSearchZip(t *testing.T, name string, files map[string]string) {
	t.Helper()
	if _, ok := files["META-INF/"]; !ok {
		files["META-INF/"] = ""
	}
	if _, ok := files["META-INF/MANIFEST.MF"]; !ok {
		files["META-INF/MANIFEST.MF"] = "Manifest-Version: 1.0\n\n"
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for member, body := range files {
		w, err := zw.Create(member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
