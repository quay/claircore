package crda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

var pypiRepo = claircore.Repository{
	Name: "python",
	URI:  "https://python.org",
}

func (tc matcherTestcase) Run(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	got, err := tc.Matcher.QueryRemoteMatcher(ctx, tc.R)
	// RemoteMatcher never throws error, it just logs it.
	if err != nil {
		t.Errorf("RemoteMatcher error %v", err)
	}
	for k, want := range tc.Expected {
		got, ok := got[k]
		if !ok {
			t.Errorf("Expected key %s not found", k)
		}
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}

type matcherTestcase struct {
	Expected map[string][]*claircore.Vulnerability
	Matcher  *matcher
	Name     string
	R        []*claircore.IndexRecord
}

func mkMatcher(t *testing.T, srv *httptest.Server) *matcher {
	url, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newMatcher("pypi", "", withClient(srv.Client()), withURL(url))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMatcherURL(t *testing.T) {
	expectedURL := "https://gw.api.openshift.io/api/v2/vulnerability-analysis?user_key=algo"
	url, err := url.Parse("https://gw.api.openshift.io/api/v2/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = newMatcher("pypi", "algo", withURL(url))
	if err != nil {
		t.Fatal(err)
	}
	m2, err := newMatcher("maven", "algo", withURL(url))
	if err != nil {
		t.Fatal(err)
	}
	if m2.url.String() != expectedURL {
		t.Fatalf("Invalid url %s, expected %s", m2.url.String(), expectedURL)
	}
}

func TestRemoteMatcher(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var vulnRequest VulnRequest
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&vulnRequest); err != nil {
			t.Error(err)
		}
		var resp []VulnReport
		for _, p := range vulnRequest.Packages {
			res := VulnReport{
				Name:    p.Name,
				Version: p.Version,
			}
			testLocalPath := fmt.Sprintf("testdata/%s/%s/%s.json", vulnRequest.Ecosystem, p.Name, p.Version)
			t.Logf("serving request for %v", testLocalPath)
			jsonOut, err := os.ReadFile(testLocalPath)
			if err != nil {
				t.Log(err)
				continue
			}
			if err := json.Unmarshal(jsonOut, &res); err != nil {
				t.Errorf("mock server unmarshal error %v", err)
				continue
			}
			resp = append(resp, res)
		}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	tt := []matcherTestcase{
		{
			Name:     "pypi/empty",
			R:        []*claircore.IndexRecord{},
			Expected: map[string][]*claircore.Vulnerability{},
			Matcher:  mkMatcher(t, srv),
		},
		{
			Name: "pypi/pyyaml",
			R: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:      "pyyaml",
						Name:    "pyyaml",
						Version: "5.3",
					},
					Repository: &pypiRepo,
				},
				{
					Package: &claircore.Package{
						ID:      "flask",
						Name:    "flask",
						Version: "1.1.0",
					},
					Repository: &pypiRepo,
				},
			},
			Expected: map[string][]*claircore.Vulnerability{
				"pyyaml": {
					{
						ID:                 "SNYK-PYTHON-PYYAML-559098",
						Updater:            "CodeReadyAnalytics",
						Name:               "SNYK-PYTHON-PYYAML-559098",
						Description:        "Arbitrary Code Execution",
						Links:              "https://snyk.io/vuln/SNYK-PYTHON-PYYAML-559098",
						Severity:           "critical",
						NormalizedSeverity: claircore.Critical,
						Package: &claircore.Package{
							ID:      "pyyaml",
							Name:    "pyyaml",
							Version: "5.3",
						},
						Repo:           &pypiRepo,
						FixedInVersion: "5.3.1",
					},
				},
			},
			Matcher: mkMatcher(t, srv),
		},
		{
			Name: "pypi/none",
			R: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:      "pyyaml",
						Name:    "pyyaml",
						Version: "5.3.1",
					},
					Repository: &pypiRepo,
				},
				{
					Package: &claircore.Package{
						ID:      "flask",
						Name:    "flask",
						Version: "1.1.0",
					},
					Repository: &pypiRepo,
				},
			},
			Expected: map[string][]*claircore.Vulnerability{},
			Matcher:  mkMatcher(t, srv),
		},
		{
			Name: "pypi/pyyaml-flask",
			R: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:      "pyyaml",
						Name:    "pyyaml",
						Version: "5.3",
					},
					Repository: &pypiRepo,
				},
				{
					Package: &claircore.Package{
						ID:      "flask",
						Name:    "flask",
						Version: "0.12",
					},
					Repository: &pypiRepo,
				},
			},
			Expected: map[string][]*claircore.Vulnerability{
				"pyyaml": {
					{
						ID:                 "SNYK-PYTHON-PYYAML-559098",
						Updater:            "CodeReadyAnalytics",
						Name:               "SNYK-PYTHON-PYYAML-559098",
						Description:        "Arbitrary Code Execution",
						Links:              "https://snyk.io/vuln/SNYK-PYTHON-PYYAML-559098",
						Severity:           "critical",
						NormalizedSeverity: claircore.Critical,
						Package: &claircore.Package{
							ID:      "pyyaml",
							Name:    "pyyaml",
							Version: "5.3",
						},
						Repo:           &pypiRepo,
						FixedInVersion: "5.3.1",
					},
				},
				"flask": {
					{
						ID:                 "SNYK-PYTHON-FLASK-42185",
						Updater:            "CodeReadyAnalytics",
						Name:               "SNYK-PYTHON-FLASK-42185",
						Description:        "Improper Input Validation",
						Links:              "https://snyk.io/vuln/SNYK-PYTHON-FLASK-42185",
						Severity:           "high",
						NormalizedSeverity: claircore.High,
						Package: &claircore.Package{
							ID:      "flask",
							Name:    "flask",
							Version: "0.12",
						},
						Repo:           &pypiRepo,
						FixedInVersion: "0.12.3",
					},
					{
						ID:                 "SNYK-PYTHON-FLASK-451637",
						Updater:            "CodeReadyAnalytics",
						Name:               "SNYK-PYTHON-FLASK-451637",
						Description:        "Denial of Service (DoS)",
						Links:              "https://snyk.io/vuln/SNYK-PYTHON-FLASK-451637",
						Severity:           "high",
						NormalizedSeverity: claircore.High,
						Package: &claircore.Package{
							ID:      "flask",
							Name:    "flask",
							Version: "0.12",
						},
						Repo:           &pypiRepo,
						FixedInVersion: "1.0",
					},
				},
			},
			Matcher: mkMatcher(t, srv),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
