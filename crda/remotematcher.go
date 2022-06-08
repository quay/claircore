package crda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher       = (*matcher)(nil)
	_ driver.RemoteMatcher = (*matcher)(nil)
)

const (
	batchSize     = 10
	defaultURL    = "https://gw.api.openshift.io/api/v2/"
	defaultSource = "clair-upstream"
)

var supportedEcosystems = []string{"pypi", "maven"}

// matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type matcher struct {
	client    *http.Client
	url       *url.URL
	ecosystem string
	source    string
}

// Build struct to model CRDA V2 ComponentAnalysis response which
// delivers Snyk sourced Vulnerability information.
type Vulnerability struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	FixedIn  []string `json:"fixed_in"`
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

// option controls the configuration of a Matcher.
type option func(*matcher) error

// newMatcher returns a configured Matcher or reports an error.
func newMatcher(ecosystem string, key string, opt ...option) (*matcher, error) {
	if ecosystem == "" {
		return nil, fmt.Errorf("empty ecosystem")
	}
	m := matcher{
		ecosystem: ecosystem,
	}

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
	m.url.Path = path.Join(m.url.Path, `vulnerability-analysis`)
	m.url.ForceQuery = true
	v := m.url.Query()
	v.Set("user_key", key)
	m.url.RawQuery = v.Encode()
	if m.source == "" {
		m.source = defaultSource
	}
	// The CRDA remote matcher doesn't use the clair roundtripper
	// client as the ratelimiting doesn't apply and a specific
	// timeout is preferred.
	m.client = &http.Client{Timeout: 5 * time.Second}

	return &m, nil
}

// WithClient sets the http.Client that the matcher should use for requests.
func withClient(c *http.Client) option {
	return func(m *matcher) error {
		m.client = c
		return nil
	}
}

// WithURL sets the URL that the matcher should use for requests.
func withURL(u *url.URL) option {
	return func(m *matcher) error {
		if u == nil {
			return nil
		}
		urlClone := *u
		m.url = &urlClone
		return nil
	}
}

// WithSource sets the source that the matcher should use for requests.
func withSource(source string) option {
	return func(m *matcher) error {
		m.source = source
		return nil
	}
}

// Name implements driver.Matcher.
func (m *matcher) Name() string { return fmt.Sprintf("crda-%s", m.ecosystem) }

// Filter implements driver.Matcher.
func (m *matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Repository == nil {
		return false
	}
	return record.Repository.Name == m.ecosystem
}

// Query implements driver.Matcher.
func (*matcher) Query() []driver.MatchConstraint {
	panic("unreachable")
}

// Vulnerable implements driver.Matcher.
func (*matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// RemoteMatcher can match Package and Vulnerability.
	panic("unreachable")
}

// QueryRemoteMatcher implements driver.RemoteMatcher.
func (m *matcher) QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "crda/Matcher.QueryRemoteMatcher")
	zlog.Debug(ctx).
		Int("records", len(records)).
		Msg("request")

	// map Package{name@version} to Package to associate it with Vulnerability.
	packageVersionToIndexRecord := make(map[string]*claircore.IndexRecord)
	key := func(Name, Version string) string {
		return fmt.Sprintf("%s@%s", Name, Version)
	}
	for _, ir := range records {
		packageVersionToIndexRecord[key(ir.Package.Name, ir.Package.Version)] = ir
	}

	results := make(map[string][]*claircore.Vulnerability)
	vrs := m.invokeComponentAnalysesInBatch(ctx, records)

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

func (m *matcher) invokeComponentAnalysesInBatch(ctx context.Context, records []*claircore.IndexRecord) []*VulnReport {
	ctrlC := make(chan []*VulnReport, len(records))
	results := []*VulnReport{}
	var wg sync.WaitGroup
	ct := len(records) / batchSize
	if len(records)%batchSize != 0 {
		ct++
	}
	wg.Add(ct)
	for start := 0; start < len(records); start += batchSize {
		start := start
		end := start + batchSize
		if end > len(records) {
			end = len(records)
		}
		go func() {
			defer wg.Done()
			vulns, err := m.invokeComponentAnalyses(ctx, records[start:end])
			if err != nil {
				zlog.Error(ctx).Err(err).Msg("remote api call failure")
				return
			}
			ctrlC <- vulns
		}()
	}
	wg.Wait()
	close(ctrlC)

	for res := range ctrlC {
		results = append(results, res...)
	}

	return results
}

func (m *matcher) invokeComponentAnalyses(ctx context.Context, records []*claircore.IndexRecord) ([]*VulnReport, error) {
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
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	// A request shouldn't go beyond 5s.
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodPost, m.url.String(), bytes.NewReader(reqBody))
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
	switch res.StatusCode {
	case http.StatusOK:
	default:
		var buf bytes.Buffer
		buf.ReadFrom(&io.LimitedReader{R: res.Body, N: 256})
		return nil, fmt.Errorf("reported error: %q (body: %q)", res.Status, buf.String())
	}
	var vulnReport []*VulnReport
	if err := json.NewDecoder(res.Body).Decode(&vulnReport); err != nil {
		return nil, err
	}
	return vulnReport, nil
}
