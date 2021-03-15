package crda

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/zlog"
)

var (
	pypiRepo = claircore.Repository{
		Name: "python",
		URI:  "https://python.org",
	}
)

func (tc matcherTestcase) Run(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	got, err := tc.Matcher.QueryRemoteMatcher(ctx, tc.R)
	// RemoteMatcher never throws error, it just logs it.
	if err != nil {
		t.Errorf("RemoteMatcher error %v", err)
	}
	for k, expectedVulns := range tc.Expected {
		got, ok := got[k]
		if !ok {
			t.Errorf("Expected key %s not found", k)
		}
		if diff := cmp.Diff(expectedVulns, got); diff != "" {
			t.Errorf("Vuln mismatch (-want, +got):\n%s", diff)
		}
	}
}

type matcherTestcase struct {
	Name     string
	R        []*claircore.IndexRecord
	Expected map[string][]*claircore.Vulnerability
	Matcher  *Matcher
}

func newMatcher(t *testing.T, srv *httptest.Server) *Matcher {
	url, _ := url.Parse(srv.URL)
	m, err := NewMatcher(WithClient(srv.Client()), WithURL(url))
	if err != nil {
		t.Errorf("there should be no err %v", err)
	}
	return m
}

func TestRemoteMatcher(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathWithoutAPIPrefix := strings.Replace(r.URL.Path, "/api/v2/component-analyses/", "", 1)
		testLocalPath := filepath.Join("testdata", pathWithoutAPIPrefix) + ".json"
		t.Logf("serving request for %v", testLocalPath)
		http.ServeFile(w, r, testLocalPath)
	}))
	defer srv.Close()

	tt := []matcherTestcase{
		{
			Name:     "pypi/empty",
			R:        []*claircore.IndexRecord{},
			Expected: map[string][]*claircore.Vulnerability{},
			Matcher:  newMatcher(t, srv),
		},
		{
			Name: "pypi/{pyyaml-vuln,flask-novuln}",
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
				"pyyaml": []*claircore.Vulnerability{
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
			Matcher: newMatcher(t, srv),
		},
		{
			Name: "pypi/{pyyaml-novuln,flask-novuln}",
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
			Matcher:  newMatcher(t, srv),
		},
		{
			Name: "pypi/{pyyaml-vuln,flask-vuln}",
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
				"pyyaml": []*claircore.Vulnerability{
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
				"flask": []*claircore.Vulnerability{
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
						ID:                 "SNYK-PYTHON-FLASK-42185-xx",
						Updater:            "CodeReadyAnalytics",
						Name:               "SNYK-PYTHON-FLASK-42185-xx",
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
						FixedInVersion: "0.12.3, 0.12.4",
					},
				},
			},
			Matcher: newMatcher(t, srv),
		}}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
