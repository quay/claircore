package crda

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	m, err := NewMatcher("pypi", WithClient(srv.Client()), WithURL(url))
	if err != nil {
		t.Errorf("there should be no err %v", err)
	}
	return m
}

func TestRemoteMatcher(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := ioutil.ReadAll(r.Body)
		var vulnRequest VulnRequest
		err := json.Unmarshal(data, &vulnRequest)
		if err != nil {
			t.Errorf("mock server unmarshall error %v", err)
		}
		var resp []VulnReport
		for _, p := range vulnRequest.Packages {
			res := VulnReport{
				Name:    p.Name,
				Version: p.Version,
			}
			testLocalPath := fmt.Sprintf("testdata/%s/%s/%s.json", vulnRequest.Ecosystem, p.Name, p.Version)
			t.Logf("serving request for %v", testLocalPath)
			jsonOut, err := ioutil.ReadFile(testLocalPath)
			if err == nil {
				err = json.Unmarshal(jsonOut, &res)
				if err != nil {
					t.Errorf("mock server unmarshall error %v", err)
				}
			}
			resp = append(resp, res)
		}
		out, err := json.Marshal(&resp)
		if err != nil {
			t.Errorf("mock server marshall error %v", err)
		}
		w.Write(out)
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
