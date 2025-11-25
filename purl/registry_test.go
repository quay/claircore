package purl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/package-url/packageurl-go"

	"github.com/quay/claircore"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/toolkit/types/cpe"
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
				r.RegisterDetector(indexer.PackageScanner(fakeScanner{}), func(ctx context.Context, ir *claircore.IndexRecord) (packageurl.PackageURL, error) {
					return packageurl.PackageURL{Type: "x", Name: ir.Package.Name, Version: ir.Package.Version}, nil
				})
				return r
			},
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Kind:     claircore.BINARY,
					Name:     "pkg",
					Version:  "1.0.0",
					Detector: &claircore.Detector{Name: "fake-scanner"},
				},
			},
			want: packageurl.PackageURL{Type: "x", Name: "pkg", Version: "1.0.0"},
		},
		{
			name: "unknown scanner returns error",
			reg:  func() *Registry { return NewRegistry() },
			ir: &claircore.IndexRecord{
				Package: &claircore.Package{
					Detector: &claircore.Detector{Name: "does-not-exist"},
				},
			},
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
				var eud ErrUnknownDetector
				if !errors.As(err, &eud) {
					t.Fatalf("expected ErrUnPurlable, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Generate error: %v", err)
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Fatalf("purl mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func mockTransformer(repoMap map[string][]string) func(ctx context.Context, p *packageurl.PackageURL) error {
	return func(ctx context.Context, p *packageurl.PackageURL) error {
		// It has already been transformed, or doesn't need to be.
		if _, ok := p.Qualifiers.Map()["repository_cpes"]; ok {
			return nil
		}
		repoid, ok := p.Qualifiers.Map()["repository_id"]
		if !ok {
			return nil
		}
		if cpes, ok := repoMap[repoid]; ok {
			cpesStr := strings.Join(cpes, ",")
			p.Qualifiers = append(p.Qualifiers, packageurl.Qualifier{Key: "repository_cpes", Value: cpesStr})
		}
		return nil
	}
}

func TestRegistryParse(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		reg     func() *Registry
		p       packageurl.PackageURL
		want    []*claircore.IndexRecord
		wantErr bool
	}{
		{
			name: "rhel purl parser no repository_id",
			reg: func() *Registry {
				r := NewRegistry()
				r.RegisterPurlType("rpm", "redhat", rhel.ParseRPMPURL, mockTransformer(map[string][]string{"rhel-9-for-x86_64-baseos-rpms": {"cpe:/o:redhat:enterprise_linux:9::baseos"}}))
				return r
			},
			p:    packageurl.PackageURL{Type: "rpm", Namespace: "redhat", Name: "bash", Version: "4.4.20-5.el8"},
			want: []*claircore.IndexRecord{},
		},
		{
			name: "rhel purl parser invalid repository_id",
			reg: func() *Registry {
				r := NewRegistry()
				r.RegisterPurlType("rpm", "redhat", rhel.ParseRPMPURL, mockTransformer(map[string][]string{"rhel-9-for-x86_64-baseos-rpms": {"cpe:/o:redhat:enterprise_linux:9::baseos"}}))
				return r
			},
			p: packageurl.PackageURL{
				Type:       "rpm",
				Namespace:  "redhat",
				Name:       "bash",
				Version:    "4.4.20-5.el8",
				Qualifiers: packageurl.Qualifiers{packageurl.Qualifier{Key: "repository_id", Value: "not_valid"}},
			},
			want: []*claircore.IndexRecord{},
		},
		{
			name: "rhel purl parser to IndexRecords with RHEL repository transformer",
			reg: func() *Registry {
				r := NewRegistry()
				r.RegisterPurlType("rpm", "redhat", rhel.ParseRPMPURL, mockTransformer(map[string][]string{"rhel-9-for-x86_64-baseos-rpms": {"cpe:/o:redhat:enterprise_linux:9::baseos"}}))
				return r
			},
			p: packageurl.PackageURL{
				Type:       "rpm",
				Namespace:  "redhat",
				Name:       "bash",
				Version:    "4.4.20-5.el8",
				Qualifiers: packageurl.Qualifiers{packageurl.Qualifier{Key: "repository_id", Value: "rhel-9-for-x86_64-baseos-rpms"}},
			},
			want: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name:    "bash",
						Version: "4.4.20-5.el8",
					},
					Repository: &claircore.Repository{
						CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:9::baseos"),
						Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
						Key:  "rhel-cpe-repository",
					},
				},
			},
		},
		{
			name: "rhel purl parser to IndexRecords with RHEL repository transformer multi CPEs",
			reg: func() *Registry {
				r := NewRegistry()
				r.RegisterPurlType("rpm", "redhat", rhel.ParseRPMPURL, mockTransformer(map[string][]string{"rhel-9-for-x86_64-rpms-multi": {"cpe:/o:redhat:enterprise_linux:9::baseos", "cpe:/a:redhat:enterprise_linux:9::appstream"}}))
				return r
			},
			p: packageurl.PackageURL{
				Type:       "rpm",
				Namespace:  "redhat",
				Name:       "bash",
				Version:    "4.4.20-5.el8",
				Qualifiers: packageurl.Qualifiers{packageurl.Qualifier{Key: "repository_id", Value: "rhel-9-for-x86_64-rpms-multi"}},
			},
			want: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						Name:    "bash",
						Version: "4.4.20-5.el8",
					},
					Repository: &claircore.Repository{
						CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:9::baseos"),
						Name: "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
						Key:  "rhel-cpe-repository",
					},
				},
				{
					Package: &claircore.Package{
						Name:    "bash",
						Version: "4.4.20-5.el8",
					},
					Repository: &claircore.Repository{
						CPE:  cpe.MustUnbind("cpe:/a:redhat:enterprise_linux:9::appstream"),
						Name: "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:*:*:*:*:*",
						Key:  "rhel-cpe-repository",
					},
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
				var eup ErrUnhandledPurl
				if !errors.As(err, &eup) {
					t.Fatalf("expected ErrUnknownPurlType, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Fatalf("index record mismatch (-got +want):\n%s", diff)
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

	repoMap := map[string][]string{
		"rhel-9-for-x86_64-baseos-rpms": {"cpe:/o:redhat:enterprise_linux:9::baseos"},
	}

	newReg := func() *Registry {
		r := NewRegistry()
		r.RegisterDetector(gobin.Detector{}, gobin.GeneratePURL)
		r.RegisterPurlType(gobin.PURLType, NoneNamespace, gobin.ParsePURL)
		r.RegisterDetector(rhel.PackageScanner{}, rhel.GenerateRPMPURL)
		r.RegisterPurlType(rhel.PURLType, rhel.PURLNamespace, rhel.ParseRPMPURL, mockTransformer(repoMap))
		return r
	}

	tests := []struct {
		name                 string
		spdxPath             string
		expectedIndexRecords int
	}{
		{name: "GoHummingbird", spdxPath: "testdata/go-hummingbird.spdx.json", expectedIndexRecords: 1},
		{name: "UBILatest", spdxPath: "testdata/ubi_latest_spdx.json", expectedIndexRecords: 185},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := newReg()

			f, err := os.Open(tt.spdxPath)
			if err != nil {
				t.Fatalf("open spdx: %v", err)
			}
			defer f.Close()

			var doc spdxDoc
			if err := json.NewDecoder(f).Decode(&doc); err != nil {
				t.Fatalf("decode spdx: %v", err)
			}

			var numPURLs int
			var gotIndexRecords int
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
						var e ErrUnhandledPurl
						if errors.As(err, &e) {
							// Accept unknown types; not yet defined in the registry.
							continue
						}
						t.Fatalf("registry parse %q: %v", pu.String(), err)
					}
					for _, ir := range got {
						gotIndexRecords++
						if ir == nil || ir.Package == nil || ir.Package.Name == "" {
							t.Fatalf("invalid indexrecord for %q: %#v", pu.String(), ir)
						}
						t.Logf("parsed index record for %q: %#v", pu.String(), ir.Repository)
					}
				}
			}
			t.Logf("parsed %d PURLs from %s", numPURLs, tt.spdxPath)
			if gotIndexRecords != tt.expectedIndexRecords {
				t.Fatalf("expected %d index records, got %d", tt.expectedIndexRecords, gotIndexRecords)
			}
		})
	}
}
