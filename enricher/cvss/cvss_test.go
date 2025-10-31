package cvss

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
)

func TestConfigure(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	tt := []configTestcase{
		{
			Name: "None",
		},
		{
			Name: "OK",
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "http://example.com/"
				cfg.FeedRoot = &s
				return nil
			},
		},
		{
			Name:   "UnmarshalError",
			Config: func(_ any) error { return errors.New("expected error") },
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected unmarshal error")
				}
			},
		},
		{
			Name: "TrailingSlash",
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "http://example.com"
				cfg.FeedRoot = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected trailing slash error")
				}
			},
		},
		{
			Name: "BadURL",
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "http://[notaurl:/"
				cfg.FeedRoot = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected URL parse error")
				}
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx))
	}
}

type configTestcase struct {
	Config func(any) error
	Check  func(*testing.T, error)
	Name   string
}

func (tc configTestcase) Run(ctx context.Context) func(*testing.T) {
	e := &Enricher{}
	return func(t *testing.T) {
		ctx := test.Logging(t, ctx)
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

func noopConfig(_ any) error { return nil }

func TestFetch(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	srv := mockServer(t)
	tt := []fetchTestcase{
		{
			Name: "Initial",
		},
		{
			Name: "InvalidHint",
			Hint: `{bareword`,
			Check: func(t *testing.T, rc io.ReadCloser, fp driver.Fingerprint, err error) {
				if rc != nil {
					t.Error("got non-nil ReadCloser")
				}
				if got, want := driver.Fingerprint(""), fp; got != want {
					t.Errorf("bad fingerprint: got: %q, want: %q", got, want)
				}
				t.Logf("got error: %v", err)
				if err == nil {
					t.Error("wanted non-nil error")
				}
			},
		},
		{
			Name: "Unchanged",
			Hint: func() string {
				// This is copied out of the metafile in testdata:
				const h = `D165E29D8D911F3F1E0919A5C1E8C423B14AF1C38F57847DD0A8CC9DBD027618`
				var b strings.Builder
				b.WriteByte('{')
				for y, lim := firstYear, time.Now().Year(); y <= lim; y++ {
					fmt.Fprintf(&b, `"%d":%q`, y, h)
					if y != lim {
						b.WriteByte(',')
					}
				}
				b.WriteByte('}')
				return b.String()
			}(),
			Check: func(t *testing.T, rc io.ReadCloser, _ driver.Fingerprint, err error) {
				if rc != nil {
					t.Error("got non-nil ReadCloser")
				}
				t.Logf("got error: %v", err)
				if !errors.Is(err, driver.Unchanged) {
					t.Errorf("wanted %v", driver.Unchanged)
				}
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

func (tc fetchTestcase) Run(ctx context.Context, srv *httptest.Server) func(*testing.T) {
	e := &Enricher{}
	return func(t *testing.T) {
		ctx := test.Logging(t)
		f := func(i any) error {
			cfg, ok := i.(*Config)
			if !ok {
				t.Fatal("assertion failed")
			}
			u := srv.URL + "/"
			cfg.FeedRoot = &u
			return nil
		}
		if err := e.Configure(ctx, f, srv.Client()); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		rc, fp, err := e.FetchEnrichment(ctx, driver.Fingerprint(tc.Hint))
		if rc != nil {
			defer rc.Close()
		}
		if tc.Check == nil {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			return
		}
		tc.Check(t, rc, fp, err)
	}
}

func mockServer(t *testing.T) *httptest.Server {
	const root = `testdata/`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Ext(r.URL.Path) {
		case ".gz": // return the gzipped feed
			f, err := os.Open(filepath.Join(root, "feed.json"))
			if err != nil {
				t.Errorf("open failed: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				break
			}
			defer f.Close()
			gz := gzip.NewWriter(w)
			defer gz.Close()
			if _, err := io.Copy(gz, f); err != nil {
				t.Errorf("write error: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				break
			}
		case ".meta": // return the metafile
			http.ServeFile(w, r, filepath.Join(root, "feed.meta"))
		default:
			t.Errorf("unknown request path: %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
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
		ctx := test.Logging(t, ctx)
		f := func(i any) error {
			cfg, ok := i.(*Config)
			if !ok {
				t.Fatal("assertion failed")
			}
			u := srv.URL + "/"
			cfg.FeedRoot = &u
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
		if tc.Check == nil {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			return
		}
		tc.Check(t, rs, err)
	}
}

func TestEnrich(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	feedIn, err := os.Open("testdata/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := newItemFeed(2016, feedIn)
	if err != nil {
		t.Error(err)
	}
	g := &fakeGetter{itemFeed: f}
	r := &claircore.VulnerabilityReport{
		Vulnerabilities: map[string]*claircore.Vulnerability{
			"-1": {
				// Not a CVE
				Name: "GO-007",
			},
			"1": {
				// Legitimate CVE
				Name: "CVE-2016-2781",
			},
			"6004": {
				// Unassigned CVE
				Name: "CVE-2016-0001",
			},
			"6005": {
				//  Check description isn't considered
				Name:        "CVE-2016-3674",
				Description: "CVE-2016-2781 duplicate",
			},
		},
	}
	e := &Enricher{}
	kind, es, err := e.Enrich(ctx, g, r)
	if err != nil {
		t.Error(err)
	}
	if got, want := kind, Type; got != want {
		t.Errorf("got: %q, want: %q", got, want)
	}
	want := map[string][]map[string]any{
		"1": {{
			"version":               "3.0",
			"vectorString":          "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
			"attackVector":          "LOCAL",
			"attackComplexity":      "LOW",
			"privilegesRequired":    "LOW",
			"userInteraction":       "NONE",
			"scope":                 "CHANGED",
			"confidentialityImpact": "NONE",
			"integrityImpact":       "HIGH",
			"availabilityImpact":    "NONE",
			"baseScore":             6.5,
			"baseSeverity":          "MEDIUM",
		}},
		"6005": {{
			"version":               "3.1",
			"vectorString":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"attackVector":          "NETWORK",
			"attackComplexity":      "LOW",
			"privilegesRequired":    "NONE",
			"userInteraction":       "NONE",
			"scope":                 "UNCHANGED",
			"confidentialityImpact": "HIGH",
			"integrityImpact":       "NONE",
			"availabilityImpact":    "NONE",
			"baseScore":             7.5,
			"baseSeverity":          "HIGH",
		}},
	}
	got := map[string][]map[string]any{}
	if err := json.Unmarshal(es[0], &got); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

type fakeGetter struct {
	*itemFeed
	res []driver.EnrichmentRecord
}

func (f *fakeGetter) GetEnrichment(_ context.Context, tags []string) ([]driver.EnrichmentRecord, error) {
	id := tags[0]
	for _, v := range f.items {
		if v.CVE.ID != id {
			continue
		}
		for _, cvss := range v.CVE.Metrics.V31 {
			if cvss.Type != "Primary" {
				continue
			}
			r := []driver.EnrichmentRecord{
				{Tags: tags, Enrichment: cvss.CVSS},
			}
			f.res = r
			return r, nil
		}
		for _, cvss := range v.CVE.Metrics.V30 {
			if cvss.Type != "Primary" {
				continue
			}
			r := []driver.EnrichmentRecord{
				{Tags: tags, Enrichment: cvss.CVSS},
			}
			f.res = r
			return r, nil
		}
	}
	return nil, nil
}
