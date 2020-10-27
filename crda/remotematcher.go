package crda

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher       = (*Matcher)(nil)
	_ driver.RemoteMatcher = (*Matcher)(nil)
)

const (
	// Bounded concurrency limit.
	defaultRequestConcurrency = 10
	defaultURL                = "https://f8a-analytics-2445582058137.production.gw.apicast.io/?user_key=9e7da76708fe374d8c10fa752e72989f"
	defaultPath               = "/api/v2/component-analyses/pypi/%s/%s"
)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type Matcher struct {
	client             *http.Client
	url                *url.URL
	requestConcurrency int
}

// Build struct to model CRDA V2 ComponentAnalysis response which
// delivers Snyk sourced Vulnerability information.
type Vulnerability struct {
	ID       string   `json:"vendor_cve_ids"`
	CVSS     string   `json:"cvss"`
	CVES     []string `json:"cve_ids"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	FixedIn  []string `json:"fixed_in"`
}

type Analyses struct {
	Vulnerabilities []Vulnerability `json:"vulnerability"`
}

type VulnReport struct {
	RecommendedVersion string   `json:"recommended_versions"`
	Message            string   `json:"message"`
	Analyses           Analyses `json:"component_analyses"`
}

// Option controls the configuration of a Matcher.
type Option func(*Matcher) error

// NewMatcher returns a configured Matcher or reports an error.
func NewMatcher(opt ...Option) (*Matcher, error) {
	m := Matcher{}
	for _, f := range opt {
		if err := f(&m); err != nil {
			return nil, err
		}
	}

	if m.url == nil {
		var err error
		m.url, err = url.Parse(defaultURL)
		if err != nil {
			return nil, err
		}
	}
	if m.client == nil {
		m.client = http.DefaultClient
	}
	// defaults to a sane concurrency limit.
	if m.requestConcurrency < 1 {
		m.requestConcurrency = defaultRequestConcurrency
	}

	return &m, nil
}

// WithClient sets the http.Client that the matcher should use for requests.
//
// If not passed to NewMatcher, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(m *Matcher) error {
		m.client = c
		return nil
	}
}

// WithHost sets the server host name that the matcher should use for requests.
//
// If not passed to NewMatcher, defaultHost will be used.
func WithURL(uri string) Option {
	u, err := url.Parse(uri)
	return func(m *Matcher) error {
		if err != nil {
			return err
		}
		m.url = u
		return nil
	}
}

// WithRequestConcurrency sets the concurrency limit for the network calls.
//
// If not passed to NewMatcher, a defaultRequestConcurrency will be used.
func WithRequestConcurrency(requestConcurrency int) Option {
	return func(m *Matcher) error {
		m.requestConcurrency = requestConcurrency
		return nil
	}
}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "crda" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Package.NormalizedVersion.Kind == "pep440"
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	panic("unreachable")
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// RemoteMatcher can match Package and Vulnerability.
	panic("unreachable")
}

// QueryRemoteMatcher implements driver.RemoteMatcher.
func (m *Matcher) QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "crda/remotematcher.QueryRemoteMatcher"))
	zlog.Debug(ctx).
		Int("records", len(records)).
		Msg("request")

	ctrlC, errorC := m.fetchVulnerabilities(ctx, records)
	results := make(map[string][]*claircore.Vulnerability)
	for r := range ctrlC {
		for _, vuln := range r {
			results[vuln.Package.ID] = append(results[vuln.Package.ID], vuln)
		}
	}
	err := <-errorC // guaranteed to have an err or be closed.
	// Don't propagate error, log and move on.
	if err != nil {
		zlog.Error(ctx).Err(err).Msg("remote api call failure")
	}
	zlog.Debug(ctx).
		Int("vulnerabilities", len(results)).
		Msg("response")
	return results, nil
}

func (m *Matcher) fetchVulnerabilities(ctx context.Context, records []*claircore.IndexRecord) (<-chan []*claircore.Vulnerability, <-chan error) {
	inC := make(chan *claircore.IndexRecord, m.requestConcurrency)
	ctrlC := make(chan []*claircore.Vulnerability, m.requestConcurrency)
	errorC := make(chan error, 1)
	go func() {
		defer close(errorC)
		defer close(ctrlC)
		var g errgroup.Group
		for _, record := range records {
			g.Go(func() error {
				vulns, err := m.componentAnalyses(ctx, <-inC)
				if err != nil {
					return err
				}
				ctrlC <- vulns
				return nil
			})
			inC <- record
		}
		close(inC)
		if err := g.Wait(); err != nil {
			errorC <- err
		}
	}()
	return ctrlC, errorC
}

func (m *Matcher) componentAnalyses(ctx context.Context, record *claircore.IndexRecord) ([]*claircore.Vulnerability, error) {
	reqUrl := url.URL{
		Scheme:   m.url.Scheme,
		Host:     m.url.Host,
		Path:     fmt.Sprintf(defaultPath, record.Package.Name, record.Package.Version),
		RawQuery: m.url.RawQuery,
	}

	req := http.Request{
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {"claircore/crda/RemoteMatcher"}},
		URL:        &reqUrl,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       reqUrl.Host,
	}
	// A request shouldn't go beyound 5s.
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := m.client.Do(req.WithContext(tctx))
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	} else {
		var vulnReport VulnReport
		data, _ := ioutil.ReadAll(res.Body)
		err = json.Unmarshal(data, &vulnReport)
		if err != nil {
			return nil, err
		}
		// A package can have 0 or more vulnerabilities for a version.
		var vulns []*claircore.Vulnerability
		for _, vuln := range vulnReport.Analyses.Vulnerabilities {
			vulns = append(vulns, &claircore.Vulnerability{
				ID:                 vuln.ID,
				Updater:            "CodeReadyAnalytics",
				Name:               vuln.ID,
				Description:        vuln.Title,
				Links:              vuln.URL,
				Severity:           vuln.Severity,
				NormalizedSeverity: NormalizeSeverity(vuln.Severity),
				FixedInVersion:     strings.Join(vuln.FixedIn, ", "),
				Package:            record.Package,
				Repo:               record.Repository,
			})
		}
		return vulns, nil
	}
}
