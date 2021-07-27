package crda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher             = (*Matcher)(nil)
	_ driver.RemoteMatcher       = (*Matcher)(nil)
	_ driver.MatcherConfigurable = (*Matcher)(nil)
)

const (
	// Bounded concurrency limit.
	defaultBatchSize          = 10
	defaultEndPoint           = "/api/v2/vulnerability-analysis"
	defaultRequestConcurrency = 10
	defaultURL                = "https://f8a-analytics-2445582058137.production.gw.apicast.io/api/v2/"
	defaultSource             = "clair-upstream"
	defaultKey                = "9e7da76708fe374d8c10fa752e72989f"
)

var (
	supportedEcosystems = []string{"pypi", "maven"}
)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type Matcher struct {
	batchSize          int
	client             *http.Client
	ecosystem          string
	requestConcurrency int
	url                *url.URL
	key                string
	source             string
}

// Build struct to model CRDA V2 ComponentAnalysis response which
// delivers Snyk sourced Vulnerability information.
type Vulnerability struct {
	FixedIn  []string `json:"fixed_in"`
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
}

type VulnReport struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Request model.
type Package struct {
	Name    string `json:"package"`
	Version string `json:"version"`
}

type VulnRequest struct {
	Ecosystem string    `json:"ecosystem"`
	Packages  []Package `json:"package_versions"`
}

// Option controls the configuration of a Matcher.
type Option func(*Matcher) error

// NewMatcher returns a configured Matcher or reports an error.
func NewMatcher(ecosystem string, opt ...Option) (*Matcher, error) {
	if ecosystem == "" {
		return nil, fmt.Errorf("empty ecosystem")
	}
	m := Matcher{ecosystem: ecosystem}

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

	if m.key == "" {
		m.key = defaultKey
	}

	if m.source == "" {
		m.source = defaultSource
	}

	m.url = &url.URL{
		Scheme:     m.url.Scheme,
		Host:       m.url.Host,
		Path:       defaultEndPoint,
		ForceQuery: true,
		RawQuery:   "user_key=" + m.key,
	}

	if m.client == nil {
		m.client = http.DefaultClient // TODO(hank) Remove DefaultClient
	}

	// defaults to a sane concurrency limit.
	if m.requestConcurrency < 1 {
		m.requestConcurrency = defaultRequestConcurrency
	}

	// defaults to a sane batch size.
	if m.batchSize < 1 {
		m.batchSize = defaultBatchSize
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
func WithURL(url *url.URL) Option {
	return func(m *Matcher) error {
		m.url = url
		return nil
	}
}

// WithKey sets the api key that the matcher should use for requests.
//
// If not passed to NewMatcher, defaultKey will be used.
func WithKey(key string) Option {
	return func(m *Matcher) error {
		m.key = key
		return nil
	}
}

// WithSource sets the source that the matcher should use for requests.
//
// If not passed to NewMatcher, defaultSource will be used.
func WithSource(source string) Option {
	return func(m *Matcher) error {
		m.source = source
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

// WithBatchSize sets the number of records to be batched per request.
//
// If not passed to NewMatcher, a defaultBatchSize will be used.
func WithBatchSize(batchSize int) Option {
	return func(m *Matcher) error {
		m.batchSize = batchSize
		return nil
	}
}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "crda" }

// Maps the crda ecosystem to claircore.Repository.Name.
func ecosystemToRepositoryName(ecosystem string) string {
	switch ecosystem {
	case "maven":
		return "maven"
	case "pypi":
		return "pypi"
	default:
		panic(fmt.Sprintf("unknown ecosystem %s", ecosystem))
	}
}

// Filter implements driver.Matcher.
func (m *Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Repository == nil {
		return false
	}
	return record.Repository.Name == ecosystemToRepositoryName(m.ecosystem)
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

// Config is the configuration accepted by the Matcher.
//
// By convention, it's in a map key called "crda".
type Config struct {
	URL         string `json:"url" yaml:"url"`
	Concurrency int    `json:"concurrent_requests" yaml:"concurrent_requests"`
	Source      string `json:"source" yaml:"source"`
	Key         string `json:"key" yaml:"key"`
}

// Configure implements driver.MatcherConfigurable.
func (m *Matcher) Configure(ctx context.Context, f driver.MatcherConfigUnmarshaler, c *http.Client) error {
	var cfg Config
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.Concurrency > 0 {
		m.requestConcurrency = cfg.Concurrency
	}

	if cfg.URL != "" {
		u, err := url.Parse(cfg.URL)
		if err != nil {
			return err
		}
		m.url = u
	}
	if cfg.Source != "" {
		m.source = cfg.Source
	}
	if cfg.Key != "" {
		m.key = cfg.Key
	}
	m.client = c

	return nil
}

// QueryRemoteMatcher implements driver.RemoteMatcher.
func (m *Matcher) QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "crda/Matcher.QueryRemoteMatcher"))
	zlog.Debug(ctx).
		Int("records", len(records)).
		Msg("request")

	// map Packge{name@version} to Packge to associate it with Vulnerability.
	packageVersionToIndexRecord := make(map[string]*claircore.IndexRecord)
	key := func(Name, Version string) string {
		return fmt.Sprintf("%s@%s", Name, Version)
	}
	for _, ir := range records {
		packageVersionToIndexRecord[key(ir.Package.Name, ir.Package.Version)] = ir
	}

	results := make(map[string][]*claircore.Vulnerability)
	vulnReports := m.invokeComponentAnalysesInBatch(ctx, records)

	for _, vr := range vulnReports {
		ir := packageVersionToIndexRecord[key(vr.Name, vr.Version)]

		// A package can have 0 or more vulnerabilities for a version.
		var vulns []*claircore.Vulnerability
		for _, vuln := range vr.Vulnerabilities {
			vulns = append(vulns, &claircore.Vulnerability{
				ID:                 vuln.ID,
				Updater:            "CodeReadyAnalytics",
				Name:               vuln.ID,
				Description:        vuln.Title,
				Links:              vuln.URL,
				Severity:           vuln.Severity,
				NormalizedSeverity: normalizeSeverity(vuln.Severity),
				FixedInVersion:     strings.Join(vuln.FixedIn, ", "),
				Package:            ir.Package,
				Repo:               ir.Repository,
			})
		}
		results[ir.Package.ID] = append(results[ir.Package.ID], vulns...)
	}
	zlog.Debug(ctx).
		Int("vulnerabilities", len(results)).
		Msg("response")
	return results, nil
}

func (m *Matcher) invokeComponentAnalysesInBatch(ctx context.Context, records []*claircore.IndexRecord) []*VulnReport {
	ctrlC := make(chan []*VulnReport, len(records))
	results := []*VulnReport{}
	batchSize := m.batchSize
	defer close(ctrlC)
	var g errgroup.Group
	for start := 0; start < len(records); start += batchSize {
		start := start
		end := start + batchSize
		if end > len(records) {
			end = len(records)
		}
		g.Go(func() error {
			vulns, err := m.invokeComponentAnalyses(ctx, records[start:end])
			if err != nil {
				zlog.Error(ctx).Err(err).Msg("remote api call failure")
				return nil
			}
			ctrlC <- vulns
			return nil
		})
	}
	g.Wait()

	for res := range ctrlC {
		results = append(results, res...)
	}

	return results
}

func (m *Matcher) invokeComponentAnalyses(ctx context.Context, records []*claircore.IndexRecord) ([]*VulnReport, error) {
	// prepare request.
	request := VulnRequest{
		Ecosystem: m.ecosystem,
		Packages:  make([]Package, len(records)),
	}
	for i, ir := range records {
		request.Packages[i] = Package{
			Name:    ir.Package.Name,
			Version: ir.Package.Version,
		}
	}
	// A request shouldn't go beyound 5s.
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(tctx, http.MethodPost, m.url.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", m.source)
	req.Header.Set("Content-Type", "application/json")

	res, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var vulnReport []*VulnReport
	err = json.NewDecoder(res.Body).Decode(&vulnReport)
	if err != nil {
		return nil, err
	}
	return vulnReport, nil
}
