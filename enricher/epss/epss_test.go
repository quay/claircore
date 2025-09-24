package epss

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

func TestConfigure(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	tt := []configTestcase{
		{
			Name: "None", // No configuration provided, should use default
			Check: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			},
		},
		{
			Name: "Not OK", // URL without .gz is invalid
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "http://example.com/"
				cfg.URL = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Errorf("expected invalid URL error, but got none: %v", err)
				}
			},
		},

		{
			Name:   "UnmarshalError", // Expected error on unmarshaling
			Config: func(_ any) error { return errors.New("expected error") },
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected unmarshal error, but got none")
				}
			},
		},
		{
			Name: "BadURL", // Malformed URL in URL
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "http://[notaurl:/"
				cfg.URL = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected URL parse error, but got none")
				}
			},
		},
		{
			Name: "ValidGZURL", // Proper .gz URL in URL
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "http://example.com/epss_scores-2024-10-25.csv.gz"
				cfg.URL = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("unexpected error with .gz URL: %v", err)
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx))
	}
}

func (tc configTestcase) Run(ctx context.Context) func(*testing.T) {
	e := &Enricher{}
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		f := tc.Config
		if f == nil {
			f = noopConfig
		}
		err := e.Configure(ctx, f, nil)
		if tc.Check == nil {
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			return
		}
		tc.Check(t, err)
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	srv := mockServer(t)

	tt := []fetchTestcase{
		{
			Name: "Fetch OK", // Tests successful fetch and data processing
			Check: func(t *testing.T, rc io.ReadCloser, fp driver.Fingerprint, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				defer rc.Close()
				if rc == nil {
					t.Error("expected non-nil ReadCloser for initial fetch")
				}
				if fp == driver.Fingerprint("") {
					t.Error("expected non-empty fingerprint")
				}

				// Further check if data is correctly read and structured
				data, err := io.ReadAll(rc)
				if err != nil {
					t.Errorf("failed to read enrichment data: %v", err)
				}
				t.Logf("enrichment data: %s", string(data))
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx, srv))
	}
}

type fetchTestcase struct {
	Check func(*testing.T, io.ReadCloser, driver.Fingerprint, error)
	Name  string
	Hint  string
}

type configTestcase struct {
	Config func(any) error
	Check  func(*testing.T, error)
	Name   string
}

func noopConfig(_ any) error { return nil }

func mockServer(t *testing.T) *httptest.Server {
	const root = `testdata/`

	// Define a static ETag for testing purposes
	const etagValue = `"test-etag-12345"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Ext(r.URL.Path) {
		case ".gz": // only gz baseURL is supported
			w.Header().Set("etag", etagValue)

			f, err := os.Open(filepath.Join(root, "data.csv"))
			if err != nil {
				t.Errorf("open failed: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer f.Close()

			gz := gzip.NewWriter(w)
			defer gz.Close()
			if _, err := io.Copy(gz, f); err != nil {
				t.Errorf("write error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		default:
			t.Errorf("unknown request path: %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	t.Cleanup(srv.Close)
	return srv
}

func (tc fetchTestcase) Run(ctx context.Context, srv *httptest.Server) func(*testing.T) {
	return func(t *testing.T) {
		e := &Enricher{}
		ctx := zlog.Test(ctx, t)
		configFunc := func(i any) error {
			cfg, ok := i.(*Config)
			if !ok {
				t.Fatal("expected Config type for i, but got a different type")
			}
			u := srv.URL + "/data.csv.gz"
			cfg.URL = &u
			return nil
		}

		// Configure Enricher with mock server client and custom config
		if err := e.Configure(ctx, configFunc, srv.Client()); err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		// Run FetchEnrichment and validate the result using Check
		rc, fp, err := e.FetchEnrichment(ctx, driver.Fingerprint(tc.Hint))
		if rc != nil {
			defer rc.Close()
		}
		if tc.Check != nil {
			tc.Check(t, rc, fp, err)
		} else if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	srv := mockServer(t)
	tt := []parseTestcase{
		{
			Name: "OK",
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx, srv))
	}
}

type parseTestcase struct {
	Check func(*testing.T, []driver.EnrichmentRecord, error)
	Name  string
}

func (tc parseTestcase) Run(ctx context.Context, srv *httptest.Server) func(*testing.T) {
	e := &Enricher{}
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		f := func(i any) error {
			cfg, ok := i.(*Config)
			if !ok {
				t.Fatal("assertion failed")
			}
			u := srv.URL + "/data.csv.gz"
			cfg.URL = &u
			return nil
		}
		if err := e.Configure(ctx, f, srv.Client()); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		hint := driver.Fingerprint("test-e-tag-54321")
		rc, _, err := e.FetchEnrichment(ctx, hint)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		defer rc.Close()
		rs, err := e.ParseEnrichment(ctx, rc)
		if tc.Check == nil {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			return
		}
		tc.Check(t, rs, err)
	}
}

type fakeGetter struct {
	items []driver.EnrichmentRecord
}

func (g *fakeGetter) GetEnrichment(ctx context.Context, cves []string) ([]driver.EnrichmentRecord, error) {
	var results []driver.EnrichmentRecord
	for _, cve := range cves {
		for _, item := range g.items {
			if slices.Contains(item.Tags, cve) {
				results = append(results, item)
			}
		}
	}
	return results, nil
}

func TestEnrich(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	srv := mockServer(t)
	e := &Enricher{}
	f := func(i any) error {
		cfg, ok := i.(*Config)
		if !ok {
			t.Fatal("assertion failed")
		}
		u := srv.URL + "/data.csv.gz"
		cfg.URL = &u
		return nil
	}
	if err := e.Configure(ctx, f, srv.Client()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	rc, _, err := e.FetchEnrichment(ctx, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer rc.Close()
	rs, err := e.ParseEnrichment(ctx, rc)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGetter{items: rs}
	r := &claircore.VulnerabilityReport{
		Vulnerabilities: map[string]*claircore.Vulnerability{
			"-1": {
				Name: "GO-123123",
			},
			"1": {
				Name:  "GO-123123.",
				Links: "https://example.com/CVE-2022-34667",
			},
			"6004": {
				Name: "CVE-2024-9972",
			},
			"6005": {
				Name: "CVE-2024-9986",
			},
		},
	}
	kind, es, err := e.Enrich(ctx, g, r)
	if err != nil {
		t.Error(err)
	}
	if got, want := kind, Type; got != want {
		t.Errorf("got: %q, want: %q", got, want)
	}
	want := map[string][]map[string]any{
		"1": {
			{
				"cve":          "CVE-2022-34667",
				"epss":         float64(0.00073),
				"percentile":   float64(0.32799),
				"modelVersion": "v2023.03.01",
				"date":         "2024-10-25T00:00:00+0000",
			},
		},
		"6004": {
			{
				"cve":          "CVE-2024-9972",
				"epss":         float64(0.00091),
				"percentile":   float64(0.39923),
				"modelVersion": "v2023.03.01",
				"date":         "2024-10-25T00:00:00+0000",
			},
		},
		"6005": {
			{
				"cve":          "CVE-2024-9986",
				"epss":         float64(0.00165),
				"percentile":   float64(0.53867),
				"modelVersion": "v2023.03.01",
				"date":         "2024-10-25T00:00:00+0000",
			},
		},
	}

	got := map[string][]map[string]any{}
	if err := json.Unmarshal(es[0], &got); err != nil {
		t.Error(err)
	} else {
		log.Printf("Got: %+v\n", got)

		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
