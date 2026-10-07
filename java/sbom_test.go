package java

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"

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

	format, err := bom.FormatFromName(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	seq, err := bom.LoadCDX(ctx, f, format)
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
		if len(bp.CPEs) != 1 || hint.Get("cpe") != bp.CPEs[0].String() {
			t.Fatalf("cpe hint: got %q", hint["cpe"])
		}
		if hint.Has("hash") {
			t.Fatalf("hash hint: got %q", hint["hash"])
		}
		wantDB := "sbom:sbom.cdx.json"
		if bp.Location != "" {
			wantDB += ":" + bp.Location
		}
		if pkg.PackageDB != wantDB {
			t.Fatalf("package db: got %q", pkg.PackageDB)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("jackson-databind not in fixture")
	}
}

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
	writeZip(t, filepath.Join(root, "carrier-1.0.jar"), map[string]string{
		"META-INF/sbom/dependency.cdx.json": string(searchCDX(t)),
	})
	writeZip(t, filepath.Join(root, "plain-1.0.jar"), map[string]string{
		"placeholder.txt": "plain",
	})

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&ScannerConfig{API: srv.URL}); err != nil {
		t.Fatal(err)
	}
	scanner := new(Scanner)
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

// TestSBOMSkipsCoveredJars builds a directory layer and checks the three
// layer-SBOM skip rules: a jar is dropped when its path matches a component
// location, a jar is dropped when only its digest matches, and an SBOM inside
// a jar does not cause another jar to be dropped.
func TestSBOMSkipsCoveredJars(t *testing.T) {
	ctx := test.Logging(t)
	root := t.TempDir()

	covered := writeZip(t, filepath.Join(root, "lib/covered-1.0.jar"), map[string]string{
		"placeholder.txt": "covered",
	})
	hashed := writeZip(t, filepath.Join(root, "lib/hashed-1.0.jar"), map[string]string{
		"placeholder.txt": "hashed",
	})
	writeZip(t, filepath.Join(root, "lib/other-1.0.jar"), map[string]string{
		"placeholder.txt": "other",
	})
	sibling := writeZip(t, filepath.Join(root, "lib/sibling-1.0.jar"), map[string]string{
		"placeholder.txt": "sibling",
	})
	// The carrier sorts before lib/, so a bug that recorded this document's
	// path or hash would still be able to drop the sibling.
	writeZip(t, filepath.Join(root, "aaa-app-1.0.jar"), map[string]string{
		"META-INF/sbom/dependency.cdx.json": string(cdxDoc(t,
			"pkg:maven/org.example/embedded@1.0",
			"embedded",
			"1.0",
			"lib/sibling-1.0.jar",
			sha256Hex(sibling),
		)),
		"placeholder.txt": "carrier",
	})

	writeFile(t, filepath.Join(root, "sbom.cdx.json"), cdxDoc(t,
		"pkg:maven/org.example/covered@1.0",
		"covered",
		"1.0",
		"lib/covered-1.0.jar",
		sha256Hex(covered),
	))
	// Location joins to meta/elsewhere/hashed-1.0.jar, not the real jar.
	writeFile(t, filepath.Join(root, "meta/app.cdx.json"), cdxDoc(t,
		"pkg:maven/org.example/hashed@1.0",
		"hashed",
		"1.0",
		"elsewhere/hashed-1.0.jar",
		sha256Hex(hashed),
	))

	var l claircore.Layer
	desc := claircore.LayerDescription{
		Digest:    test.RandomSHA256Digest(t).String(),
		URI:       "file://" + root,
		MediaType: "application/vnd.claircore.filesystem",
		Headers:   map[string][]string{},
	}
	if err := l.Init(ctx, &desc, nil); err != nil {
		t.Fatalf("init layer: %v", err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	pkgs, err := new(Scanner).Scan(ctx, &l)
	if err != nil {
		t.Fatal(err)
	}
	gotFile := map[string]*claircore.Package{}
	gotSBOM := map[string]*claircore.Package{}
	for _, pkg := range pkgs {
		t.Logf("%s %s %s", pkg.PackageDB, pkg.Name, pkg.Filepath)
		switch {
		case strings.HasPrefix(pkg.PackageDB, "file:"):
			gotFile[pkg.PackageDB] = pkg
		case strings.HasPrefix(pkg.PackageDB, "sbom:"):
			gotSBOM[pkg.PackageDB] = pkg
		default:
			t.Errorf("unexpected package db %q", pkg.PackageDB)
		}
	}

	for _, db := range []string{
		"file:lib/covered-1.0.jar",
		"file:lib/hashed-1.0.jar",
		"file:aaa-app-1.0.jar",
	} {
		if pkg, ok := gotFile[db]; ok {
			t.Errorf("jar was indexed from the archive: %s %s", pkg.PackageDB, pkg.Name)
		}
	}
	for _, db := range []string{
		"file:lib/other-1.0.jar",
		"file:lib/sibling-1.0.jar",
	} {
		if _, ok := gotFile[db]; !ok {
			t.Errorf("missing jar %s", db)
		}
	}
	assertSBOM(t, gotSBOM["sbom:sbom.cdx.json:lib/covered-1.0.jar"], "org.example:covered", "lib/covered-1.0.jar")
	assertSBOM(t, gotSBOM["sbom:meta/app.cdx.json:elsewhere/hashed-1.0.jar"], "org.example:hashed", "meta/elsewhere/hashed-1.0.jar")
	assertSBOM(t, gotSBOM["sbom:aaa-app-1.0.jar:META-INF/sbom/dependency.cdx.json:lib/sibling-1.0.jar"], "org.example:embedded", "aaa-app-1.0.jar")
	if len(gotFile) != 2 || len(gotSBOM) != 3 {
		t.Fatalf("got %d file packages and %d sbom packages", len(gotFile), len(gotSBOM))
	}
}

func assertSBOM(t *testing.T, pkg *claircore.Package, name, filepath string) {
	t.Helper()
	if pkg == nil {
		t.Fatalf("missing sbom package %s", name)
	}
	if pkg.Name != name {
		t.Fatalf("name: got %q, want %q", pkg.Name, name)
	}
	if pkg.Filepath != filepath {
		t.Fatalf("filepath: got %q, want %q", pkg.Filepath, filepath)
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
	doc := &cyclonedx.BOM{
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
	if err := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON).Encode(doc); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cdxDoc(t *testing.T, purl, name, version, location, sha256sum string) []byte {
	t.Helper()
	hashes := []cyclonedx.Hash{{
		Algorithm: cyclonedx.HashAlgoSHA256,
		Value:     sha256sum,
	}}
	occurrences := []cyclonedx.EvidenceOccurrence{{Location: location}}
	components := []cyclonedx.Component{{
		BOMRef:     purl,
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       name,
		Version:    version,
		PackageURL: purl,
		Hashes:     &hashes,
		Evidence:   &cyclonedx.Evidence{Occurrences: &occurrences},
	}}
	dependsOn := []string{purl}
	dependencies := []cyclonedx.Dependency{{
		Ref:          "app",
		Dependencies: &dependsOn,
	}}
	doc := &cyclonedx.BOM{
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
	err := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON).Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeZip(t *testing.T, name string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// A META-INF directory lets property lookup miss cleanly, and a version-only
	// manifest falls through to the archive name.
	if _, ok := files["META-INF/"]; !ok {
		files["META-INF/"] = ""
	}
	if _, ok := files["META-INF/MANIFEST.MF"]; !ok {
		files["META-INF/MANIFEST.MF"] = "Manifest-Version: 1.0\n\n"
	}
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
	writeFile(t, name, buf.Bytes())
	return buf.Bytes()
}

func writeFile(t *testing.T, name string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
