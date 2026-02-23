package spdx

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/purl"
	"github.com/quay/claircore/test"
)

// TestRoundTrip tests encoding an IndexReport to SPDX and decoding it back.
func TestRoundTrip(t *testing.T) {
	ctx := test.Logging(t)

	// Create a registry for both encoding and decoding.
	// For golang PURLs, we need to register parsers for all namespaces we might encounter.
	// The golang PURL generator splits package names like "github.com/example/pkg" into:
	//   namespace: github.com, name: example, subpath: pkg
	// So we need to register the parser for the "github.com" namespace.
	reg := purl.NewRegistry()
	reg.RegisterDetector(gobin.Detector{}, gobin.GeneratePURL)
	reg.RegisterPurlType(gobin.PURLType, purl.NoneNamespace, gobin.ParsePURL)
	reg.RegisterPurlType(gobin.PURLType, "github.com", gobin.ParsePURL)

	original := &claircore.IndexReport{
		State:   "IndexFinished",
		Success: true,
		Packages: map[string]*claircore.Package{
			"1": {
				ID:      "1",
				Name:    "github.com/example/pkg",
				Version: "v1.2.3",
				Kind:    claircore.BINARY,
				Detector: &claircore.Detector{
					Name:    "gobin",
					Version: "1",
					Kind:    "package",
				},
			},
		},
		Distributions: map[string]*claircore.Distribution{},
		Repositories:  map[string]*claircore.Repository{},
		Environments: map[string][]*claircore.Environment{
			"1": {{PackageDB: "go.sum"}},
		},
	}

	// Encode to SPDX.
	encoder := NewDefaultEncoder(
		WithPURLConverter(reg),
		WithDocumentName("test"),
		WithDocumentNamespace("test-ns"),
	)

	var buf bytes.Buffer
	if err := encoder.Encode(ctx, &buf, original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Decode back to IndexReport.
	decoder := NewDefaultDecoder(WithDecoderPURLConverter(reg))
	decoded, err := decoder.Decode(ctx, &buf)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Compare key fields.
	if len(decoded.Packages) != len(original.Packages) {
		t.Errorf("package count mismatch: got %d, want %d", len(decoded.Packages), len(original.Packages))
	}

	// Check that we got a package with the right name and version.
	foundPkg := false
	for _, pkg := range decoded.Packages {
		if pkg.Name == "github.com/example/pkg" && pkg.Version == "v1.2.3" {
			foundPkg = true
			break
		}
	}
	if !foundPkg {
		t.Error("expected to find package github.com/example/pkg@v1.2.3 after round-trip")
	}
}

// TestRoundTripTestdata tests round-tripping the testdata files.
func TestRoundTripTestdata(t *testing.T) {
	ctx := test.Logging(t)

	// Read all .ir.json files from testdata/round-trip.
	td := os.DirFS("testdata/round-trip")
	entries, err := fs.ReadDir(td, ".")
	if err != nil {
		t.Fatal(err)
	}

	reg := purl.NewRegistry()
	reg.RegisterPurlType(gobin.PURLType, purl.NoneNamespace, gobin.ParsePURL)

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".ir.json") {
			continue
		}

		t.Run(name, func(t *testing.T) {
			// Read the original IndexReport.
			f, err := td.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			var original claircore.IndexReport
			if err := json.NewDecoder(f).Decode(&original); err != nil {
				t.Fatal(err)
			}

			// Encode to SPDX.
			encoder := NewDefaultEncoder(
				WithDocumentName("test"),
				WithDocumentNamespace("test-ns"),
			)

			var buf bytes.Buffer
			if err := encoder.Encode(ctx, &buf, &original); err != nil {
				t.Fatal(err)
			}

			// Decode back.
			decoder := NewDefaultDecoder(WithDecoderPURLConverter(reg))
			decoded, err := decoder.Decode(ctx, &buf)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("original: %d packages, decoded: %d packages",
				len(original.Packages), len(decoded.Packages))
		})
	}
}
