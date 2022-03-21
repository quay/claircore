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
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

func TestConfigure(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	tt := []configTestcase{
		{
			Name: "None",
		},
		{
			Name: "OK",
			Config: func(i interface{}) error {
				cfg := i.(*Config)
				s := "http://example.com/"
				cfg.FeedRoot = &s
				return nil
			},
		},
		{
			Name:   "UnmarshalError",
			Config: func(_ interface{}) error { return errors.New("expected error") },
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected unmarshal error")
				}
			},
		},
		{
			Name: "TrailingSlash",
			Config: func(i interface{}) error {
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
			Config: func(i interface{}) error {
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
	Config func(interface{}) error
	Check  func(*testing.T, error)
	Name   string
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

func noopConfig(_ interface{}) error { return nil }

func TestFetch(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
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
				const h = `708083B92E47F0B25C7DD68B89ECD9EF3F2EF91403F511AE13195A596F02E02E`
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
		ctx := zlog.Test(ctx, t)
		f := func(i interface{}) error {
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
		f := func(i interface{}) error {
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
	ctx := zlog.Test(context.Background(), t)
	feedIn, err := os.Open("testdata/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := newItemFeed(2021, feedIn)
	if err != nil {
		t.Error(err)
	}
	g := &fakeGetter{itemFeed: f}
	r := &claircore.VulnerabilityReport{
		Vulnerabilities: map[string]*claircore.Vulnerability{
			"-1": {
				Description: "This is a fake vulnerability that doesn't have a CVE.",
			},
			"1": {
				Description: "This is a fake vulnerability that looks like CVE-2021-0498.",
			},
			"6004": {
				Description: "CVE-2020-6004 was unassigned",
			},
			"6005": {
				Description: "CVE-2021-0498 duplicate",
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
	want := map[string][]map[string]interface{}{
		"1": {{
			"version":               "3.1",
			"vectorString":          "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			"attackVector":          "LOCAL",
			"attackComplexity":      "LOW",
			"privilegesRequired":    "LOW",
			"userInteraction":       "NONE",
			"scope":                 "UNCHANGED",
			"confidentialityImpact": "HIGH",
			"integrityImpact":       "HIGH",
			"availabilityImpact":    "HIGH",
			"baseScore":             7.8,
			"baseSeverity":          "HIGH",
		}},
		"6005": {{
			"version":               "3.1",
			"vectorString":          "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			"attackVector":          "LOCAL",
			"attackComplexity":      "LOW",
			"privilegesRequired":    "LOW",
			"userInteraction":       "NONE",
			"scope":                 "UNCHANGED",
			"confidentialityImpact": "HIGH",
			"integrityImpact":       "HIGH",
			"availabilityImpact":    "HIGH",
			"baseScore":             7.8,
			"baseSeverity":          "HIGH",
		}},
	}
	got := map[string][]map[string]interface{}{}
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

func (f *fakeGetter) GetEnrichment(ctx context.Context, tags []string) ([]driver.EnrichmentRecord, error) {
	id := tags[0]
	for _, cve := range f.items {
		if cve.CVE.Meta.ID == id && cve.Impact.V3.CVSS != nil {
			r := []driver.EnrichmentRecord{
				{Tags: tags, Enrichment: cve.Impact.V3.CVSS},
			}
			f.res = r
			return r, nil
		}
	}
	return nil, nil
}
