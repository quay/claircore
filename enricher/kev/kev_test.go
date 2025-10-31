package kev

import (
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

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
)

// Define a static Last-Modified for testing purposes
const lastModified = `Mon, 24 Feb 2025 17:55:31 GMT`

func noopConfig(_ any) error { return nil }

func TestConfigure(t *testing.T) {
	t.Parallel()

	type configTestcase struct {
		Config func(any) error
		Check  func(*testing.T, error)
		Name   string
	}

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
				cfg.Feed = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected URL parse error, but got none")
				}
			},
		},
		{
			Name: "ValidURL", // Proper URL
			Config: func(i any) error {
				cfg := i.(*Config)
				s := "https://www.example.com/sites/default/files/feeds/known_exploited_vulnerabilities.json"
				cfg.Feed = &s
				return nil
			},
			Check: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("unexpected error with .json URL: %v", err)
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			e := &Enricher{}
			ctx := test.Logging(t)
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
		})
	}
}

func mockServer(t *testing.T) *httptest.Server {
	const root = `testdata/`
	lastModifiedTime, err := http.ParseTime(lastModified)
	if err != nil {
		t.Fatalf("unable to parse last modified time: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Ext(r.URL.Path) {
		case ".json": // only JSON is supported
			w.Header().Set("Last-Modified", lastModified)

			f, err := os.Open(filepath.Join(root, "known_exploited_vulnerabilities.json"))
			if err != nil {
				t.Errorf("open failed: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer f.Close()

			ims := r.Header.Get("If-Modified-Since")
			if ims != "" {
				imsTime, err := http.ParseTime(ims)
				if err != nil {
					t.Errorf("parse time failed: %v", err)
				}
				if lastModifiedTime.Before(imsTime) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}

			_, err = io.Copy(w, f)
			if err != nil {
				t.Errorf("copying failed: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		default:
			t.Errorf("unknown request path: %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	// The CISA KEV catalog uses HTTP/2, so might as well use it here, too.
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestFetch(t *testing.T) {
	t.Parallel()
	srv := mockServer(t)

	type fetchTestcase struct {
		Name  string
		Check func(*testing.T, io.ReadCloser, driver.Fingerprint, error)
		Hint  string
	}

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
				if fp == "" {
					t.Error("expected non-empty fingerprint")
				}
				t.Logf("fingerprint: %s", fp)

				// Further check if data is correctly read and structured
				data, err := io.ReadAll(rc)
				if err != nil {
					t.Errorf("failed to read enrichment data: %v", err)
				}
				t.Logf("enrichment: %s", string(data))

				if len(data) == 0 {
					t.Error("expected non-empty data")
				}
			},
		},
		{
			Name: "Fetch Unmodified",
			Hint: lastModified,
			Check: func(t *testing.T, rc io.ReadCloser, fp driver.Fingerprint, err error) {
				if !errors.Is(err, driver.Unchanged) {
					t.Errorf("unexpected error (or lack thereof): %v", err)
					return
				}

				if rc != nil {
					t.Error("expected nil ReadCloser for initial fetch")
				}

				if fp == "" {
					t.Error("expected non-empty fingerprint")
				}
				t.Logf("fingerprint: %s", fp)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			e := &Enricher{}
			ctx := test.Logging(t)
			configFunc := func(i any) error {
				cfg, ok := i.(*Config)
				if !ok {
					t.Fatal("expected Config type for i, but got a different type")
				}
				u := srv.URL + "/known_exploited_vulnerabilities.json"
				cfg.Feed = &u
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
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	srv := mockServer(t)

	e := &Enricher{}
	f := func(i any) error {
		cfg, ok := i.(*Config)
		if !ok {
			t.Fatal("assertion failed")
		}
		u := srv.URL + "/known_exploited_vulnerabilities.json"
		cfg.Feed = &u
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
		t.Errorf("unexpected error: %v", err)
	}
	got := make(map[string]Entry)
	for _, r := range rs {
		if len(r.Tags) != 1 {
			t.Errorf("unexpected number of tags: %d", len(r.Tags))
		}
		var entry Entry
		if err := json.Unmarshal(r.Enrichment, &entry); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		got[r.Tags[0]] = entry
	}

	want := map[string]Entry{
		"CVE-2017-3066": {
			CVE:                        "CVE-2017-3066",
			VulnerabilityName:          "Adobe ColdFusion Deserialization Vulnerability",
			CatalogVersion:             "2025.02.24",
			DateAdded:                  "2025-02-24",
			ShortDescription:           "Adobe ColdFusion contains a deserialization vulnerability in the Apache BlazeDS library that allows for arbitrary code execution.",
			RequiredAction:             "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
			DueDate:                    "2025-03-17",
			KnownRansomwareCampaignUse: "Unknown",
		},
		"CVE-2021-44228": {
			CVE:                        "CVE-2021-44228",
			VulnerabilityName:          "Apache Log4j2 Remote Code Execution Vulnerability",
			CatalogVersion:             "2025.02.24",
			DateAdded:                  "2021-12-10",
			ShortDescription:           "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
			RequiredAction:             "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.",
			DueDate:                    "2021-12-24",
			KnownRansomwareCampaignUse: "Known",
		},
	}

	if !cmp.Equal(got, want) {
		t.Errorf("unexpected result, diff = %v", cmp.Diff(got, want))
	}
}

type fakeGetter struct {
	items []driver.EnrichmentRecord
}

func (g fakeGetter) GetEnrichment(_ context.Context, cves []string) ([]driver.EnrichmentRecord, error) {
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
	ctx := test.Logging(t)
	srv := mockServer(t)

	e := &Enricher{}
	f := func(i any) error {
		cfg, ok := i.(*Config)
		if !ok {
			t.Fatal("assertion failed")
		}
		u := srv.URL + "/known_exploited_vulnerabilities.json"
		cfg.Feed = &u
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
				// Not a CVE
				Name: "GO-007",
			},
			"6004": {
				// Legitimate CVE
				Name: "CVE-2021-44228 is here",
			},
			"6005": {
				Name:  "GO-123123",
				Links: "CVE-2017-3066.com",
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
	want := map[string][]map[string]string{
		"6004": {
			{
				"cve":                           "CVE-2021-44228",
				"vulnerability_name":            "Apache Log4j2 Remote Code Execution Vulnerability",
				"catalog_version":               "2025.02.24",
				"date_added":                    "2021-12-10",
				"short_description":             "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
				"required_action":               "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.",
				"due_date":                      "2021-12-24",
				"known_ransomware_campaign_use": "Known",
			},
		},
		"6005": {
			{
				"cve":                           "CVE-2017-3066",
				"vulnerability_name":            "Adobe ColdFusion Deserialization Vulnerability",
				"catalog_version":               "2025.02.24",
				"date_added":                    "2025-02-24",
				"short_description":             "Adobe ColdFusion contains a deserialization vulnerability in the Apache BlazeDS library that allows for arbitrary code execution.",
				"required_action":               "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
				"due_date":                      "2025-03-17",
				"known_ransomware_campaign_use": "Unknown",
			},
		},
	}

	got := map[string][]map[string]string{}
	if err := json.Unmarshal(es[0], &got); err != nil {
		t.Error(err)
		return
	}

	log.Printf("Got: %+v\n", got)
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
