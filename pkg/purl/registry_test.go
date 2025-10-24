package purl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/rhel"
)

// minimal scanner for registration
type fakeScanner struct{}

func (fakeScanner) Name() string    { return "fake-scanner" }
func (fakeScanner) Version() string { return "1" }
func (fakeScanner) Kind() string    { return "package" }
func (fakeScanner) Scan(context.Context, *claircore.Layer) ([]*claircore.Package, error) {
	return nil, nil
}

func TestRegistryGenerate(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		reg     func() *Registry
		ir      *claircore.IndexRecord
		want    packageurl.PackageURL
		wantErr bool
	}{
		{
			name: "registered scanner generates purl",
			reg: func() *Registry {
				r := NewRegistry()
				r.RegisterScanner(indexer.PackageScanner(fakeScanner{}), func(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
					return packageurl.PackageURL{Type: "x", Name: ir.Package.Name, Version: ir.Package.Version}, nil
				})
				return r
			},
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					ScannerName: "fake-scanner",
					Kind:        claircore.BINARY,
					Name:        "pkg",
					Version:     "1.0.0",
				},
			},
			want: packageurl.PackageURL{Type: "x", Name: "pkg", Version: "1.0.0"},
		},
		{
			name:    "unknown scanner returns error",
			reg:     func() *Registry { return NewRegistry() },
			ir:      &claircore.IndexRecord{Package: &claircore.Package{ScannerName: "does-not-exist"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.reg()
			got, err := r.Generate(ctx, tt.ir)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				var eup ErrUnPurlable
				if !errors.As(err, &eup) {
					t.Fatalf("expected ErrUnPurlable, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Generate error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("purl mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRegistryParse(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		reg     func() *Registry
		p       packageurl.PackageURL
		want    *claircore.IndexRecord
		wantErr bool
	}{
		{
			name: "registered type parses to index record",
			reg: func() *Registry {
				r := NewRegistry()
				r.RegisterPurlType("rpm", "redhat", func(ctx context.Context, p packageurl.PackageURL) (*claircore.IndexRecord, error) {
					return &claircore.IndexRecord{Package: &claircore.Package{Name: p.Name, Version: p.Version}}, nil
				})
				return r
			},
			p: packageurl.PackageURL{Type: "rpm", Namespace: "redhat", Name: "bash", Version: "1"},
			want: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "bash",
					Version: "1",
				},
			},
		},
		{
			name:    "unknown type returns error",
			reg:     func() *Registry { return NewRegistry() },
			p:       packageurl.PackageURL{Type: "does-not-exist"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.reg()
			got, err := r.Parse(ctx, tt.p)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				var eut ErrUnknownPurl
				if !errors.As(err, &eut) {
					t.Fatalf("expected ErrUnknownPurlType, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("index record mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// minimal structures for SPDX 2.3 JSON we care about
type spdxDoc struct {
	Packages []struct {
		ExternalRefs []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func TestSPDXPURLsParseToIndexRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Build a registry with explicit built-ins.
	reg := NewRegistry()
	reg.RegisterScanner(gobin.Detector{}, gobin.GeneratePURL)
	reg.RegisterPurlType(gobin.PURLType, NoneNamespace, gobin.ParsePURL)
	reg.RegisterScanner(rhel.PackageScanner{}, rhel.GenerateRPMPURL)
	reg.RegisterPurlType(rhel.PURLType, rhel.PURLNamespace, rhel.ParseRPMPURL)

	// Use an existing SPDX document from testdata.
	const spdxPath = "testdata/go-hummingbird.spdx.json"
	f, err := os.Open(spdxPath)
	if err != nil {
		t.Fatalf("open spdx: %v", err)
	}
	defer f.Close()

	var doc spdxDoc
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		t.Fatalf("decode spdx: %v", err)
	}

	// Cycle PURLs → IndexRecords
	var numPURLs int
	for _, p := range doc.Packages {
		for _, r := range p.ExternalRefs {
			if r.ReferenceType != "purl" {
				continue
			}
			numPURLs++
			pu, err := packageurl.FromString(r.ReferenceLocator)
			if err != nil {
				t.Fatalf("parse purl %q: %v", r.ReferenceLocator, err)
			}
			got, err := reg.Parse(ctx, pu)
			if err != nil {
				var e ErrUnknownPurl
				if errors.As(err, &e) {
					// Accept unknown types; not yet defined in the registry.
					continue
				}
				t.Fatalf("registry parse %q: %v", pu.String(), err)
			}
			if got == nil || got.Package == nil || got.Package.Name == "" {
				t.Fatalf("invalid indexrecord for %q: %#v", pu.String(), got)
			}
		}
	}
	// It's acceptable that some fixtures contain no PURLs; provide a hint.
	t.Logf("parsed %d PURLs from %s", numPURLs, spdxPath)
}
