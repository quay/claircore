package crda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	defaultBatchSize          = 100
	defaultEndPoint           = "/api/v2/component-analyses"
	defaultRequestConcurrency = 10
	defaultURL                = "https://f8a-analytics-2445582058137.production.gw.apicast.io/?user_key=9e7da76708fe374d8c10fa752e72989f"
	defaultSource             = "clair-upstream"
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
}

// Build struct to model CRDA V2 ComponentAnalysis response which
// delivers Snyk sourced Vulnerability information.
type Vulnerability struct {
	ID       string   `json:"id"`
	CVSS     string   `json:"cvss"`
	CVES     []string `json:"cve_ids"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	FixedIn  []string `json:"fixed_in"`
}

type VulnReport struct {
	Name               string          `json:"package"`
	Version            string          `json:"version"`
	RecommendedVersion string          `json:"recommended_versions"`
	Message            string          `json:"message"`
	Vulnerabilities    []Vulnerability `json:"vulnerability"`
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
	m.url = &url.URL{
		Scheme:   m.url.Scheme,
		Host:     m.url.Host,
		Path:     defaultEndPoint,
		RawQuery: m.url.RawQuery,
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
}

// Configure implements driver.MatcherConfigurable.
func (m *Matcher) Configure(ctx context.Context, f driver.MatcherConfigUnmarshaler, c *http.Client) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "crda/Matcher.Configure"))
	var cfg Config
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.Concurrency > 0 {
		m.requestConcurrency = cfg.Concurrency
		zlog.Info(ctx).
			Msg("configured concurrent requests")
	}
	if cfg.URL != "" {
		u, err := url.Parse(cfg.URL)
		if err != nil {
			return err
		}
		m.url = u
		zlog.Info(ctx).
			Msg("configured API URL")
	}
	m.client = c
	zlog.Info(ctx).
		Msg("configured HTTP client")

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
	ctrlC, errorC := m.invokeComponentAnalysesInBatch(ctx, records)
	err := <-errorC // guaranteed to have an err or be closed.
	// Don't propagate error, log and move on.
	if err != nil {
		zlog.Error(ctx).Err(err).Msg("remote api call failure")
		return results, nil
	}
	for vrs := range ctrlC {
		for _, vr := range vrs {
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
					NormalizedSeverity: NormalizeSeverity(vuln.Severity),
					FixedInVersion:     strings.Join(vuln.FixedIn, ", "),
					Package:            ir.Package,
					Repo:               ir.Repository,
				})
			}
			results[ir.Package.ID] = append(results[ir.Package.ID], vulns...)
		}
	}
	zlog.Debug(ctx).
		Int("vulnerabilities", len(results)).
		Msg("response")
	return results, nil
}

func (m *Matcher) invokeComponentAnalysesInBatch(ctx context.Context, records []*claircore.IndexRecord) (<-chan []*VulnReport, <-chan error) {
	inC := make(chan []*claircore.IndexRecord, m.requestConcurrency)
	ctrlC := make(chan []*VulnReport, m.requestConcurrency)
	errorC := make(chan error, 1)
	batchSize := m.batchSize
	go func() {
		defer close(errorC)
		defer close(ctrlC)
		var g errgroup.Group
		for start := 0; start < len(records); start += batchSize {
			end := start + batchSize
			if end > len(records) {
				end = len(records)
			}
			g.Go(func() error {
				vulns, err := m.invokeComponentAnalyses(ctx, <-inC)
				if err != nil {
					return err
				}
				ctrlC <- vulns
				return nil
			})
			inC <- records[start:end]
		}
		close(inC)
		if err := g.Wait(); err != nil {
			errorC <- err
		}
	}()
	return ctrlC, errorC
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
	reqBody, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(tctx, http.MethodPost, m.url.String(), bytes.NewBuffer(reqBody))
	req.Header.Set("User-Agent", "claircore/remote_matcher")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Source-Type", defaultSource)
	res, err := m.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	var vulnReport []*VulnReport
	data, _ := ioutil.ReadAll(res.Body)
	err = json.Unmarshal(data, &vulnReport)
	if err != nil {
		return nil, err
	}
	return vulnReport, nil
}
