// Package kev provides a CISA Known Exploited Vulnerabilities enricher.
package kev

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/enricher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	_ driver.Enricher          = (*Enricher)(nil)
	_ driver.EnrichmentUpdater = (*Enricher)(nil)

	defaultFeed *url.URL
)

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.vulnerability; enricher=clair.kev schema=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json`
	// DefaultFeed is the default place to look for the CISA Known Exploited Vulnerabilities feed.
	//
	//doc:url updater
	DefaultFeed = `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

	// This appears above and must be the same.
	name = `clair.kev`
)

func init() {
	var err error
	defaultFeed, err = url.Parse(DefaultFeed)
	if err != nil {
		panic(err)
	}
}

// NewFactory creates a Factory for the CISA KEV enricher.
func NewFactory() driver.UpdaterSetFactory {
	set := driver.NewUpdaterSet()
	_ = set.Add(&Enricher{})
	return driver.StaticSet(set)
}

// Enricher provides exploit data as enrichments to a VulnerabilityReport.
//
// Configure must be called before any other methods.
type Enricher struct {
	driver.NoopUpdater
	c    *http.Client
	feed *url.URL
}

// Config is the configuration for Enricher.
type Config struct {
	Feed *string `json:"feed_root" yaml:"feed"`
}

// Configure implements driver.Configurable.
func (e *Enricher) Configure(_ context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg Config
	e.c = c
	if err := f(&cfg); err != nil {
		return err
	}
	e.feed = defaultFeed
	if cfg.Feed != nil {
		if !strings.HasSuffix(*cfg.Feed, ".json") {
			return fmt.Errorf("URL not pointing to JSON: %q", *cfg.Feed)
		}
		u, err := url.Parse(*cfg.Feed)
		if err != nil {
			return err
		}
		e.feed = u
	}
	return nil
}

// Name implements driver.Enricher and driver.EnrichmentUpdater.
func (*Enricher) Name() string { return name }

// FetchEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) FetchEnrichment(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/kev/Enricher/FetchEnrichment")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.feed.String(), nil)
	if err != nil {
		return nil, hint, err
	}
	if hint != "" {
		// Note: Though the default URL returns an etag, the server does not seem to respond
		// to the If-None-Match header. It seems like it does respond to If-Modified-Since, though,
		// so the timestamp is used as the hint.
		req.Header.Set("If-Modified-Since", string(hint))
	}
	res, err := e.c.Do(req)
	if err != nil {
		return nil, hint, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		if t := string(hint); t == "" || t != res.Header.Get("Last-Modified") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		zlog.Info(ctx).Msg("database unchanged since last fetch")
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("http response error: %s %d", res.Status, res.StatusCode)
	}
	zlog.Debug(ctx).Msg("successfully requested database")

	out, err := tmp.NewFile("", "kev.")
	if err != nil {
		return nil, hint, err
	}
	var success bool
	defer func() {
		if !success {
			if err := out.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close spool")
			}
		}
	}()

	// When originally created, the file was around 1.1MB, so
	// it seems like a good idea to buffer.
	buf := bufio.NewReader(res.Body)
	_, err = io.Copy(out, buf)
	if err != nil {
		return nil, hint, fmt.Errorf("failed to read enrichment: %w", err)
	}

	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return nil, hint, fmt.Errorf("unable to reset spool: %w", err)
	}

	success = true
	hint = driver.Fingerprint(res.Header.Get("Last-Modified"))
	zlog.Debug(ctx).
		Str("hint", string(hint)).
		Msg("using new hint")

	return out, hint, nil
}

// ParseEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) ParseEnrichment(ctx context.Context, rc io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/kev/Enricher/ParseEnrichment")

	var root Root
	buf := bufio.NewReader(rc)
	if err := json.NewDecoder(buf).Decode(&root); err != nil {
		return nil, fmt.Errorf("failed to parse enrichment: %w", err)
	}

	// The self-declared count is probably pretty accurate.
	// As of writing this, the count is 1278, so it's rather small.
	recs := make([]driver.EnrichmentRecord, 0, root.Count)
	for _, vuln := range root.Vulnerabilities {
		entry := Entry{
			CVE:                        vuln.CVEID,
			VulnerabilityName:          vuln.VulnerabilityName,
			CatalogVersion:             root.CatalogVersion,
			DateAdded:                  vuln.DateAdded,
			ShortDescription:           vuln.ShortDescription,
			RequiredAction:             vuln.RequiredAction,
			DueDate:                    vuln.DueDate,
			KnownRansomwareCampaignUse: vuln.KnownRansomwareCampaignUse,
		}
		enrichment, err := json.Marshal(&entry)
		if err != nil {
			return nil, fmt.Errorf("failed to encode enrichment: %w", err)
		}

		recs = append(recs, driver.EnrichmentRecord{
			Tags:       []string{vuln.CVEID},
			Enrichment: enrichment,
		})
	}

	return recs, nil
}

// Enrich implements driver.Enricher.
func (e *Enricher) Enrich(ctx context.Context, g driver.EnrichmentGetter, r *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/kev/Enricher/Enrich")

	m := make(map[string][]json.RawMessage)
	erCache := make(map[string][]driver.EnrichmentRecord)

	for id, v := range r.Vulnerabilities {
		t := make(map[string]struct{})
		ctx := zlog.ContextWithValues(ctx, "vuln", v.Name)

		for _, elem := range []string{
			v.Description,
			v.Name,
			v.Links,
		} {
			// Check if the element is non-empty before running the regex
			if elem == "" {
				zlog.Debug(ctx).Str("element", elem).Msg("skipping empty element")
				continue
			}

			matches := enricher.CVERegexp.FindAllString(elem, -1)
			if len(matches) == 0 {
				zlog.Debug(ctx).Str("element", elem).Msg("no CVEs found in element")
				continue
			}
			for _, m := range matches {
				t[m] = struct{}{}
			}
		}

		// Skip if no CVEs were found
		if len(t) == 0 {
			zlog.Debug(ctx).Msg("no CVEs found in vulnerability metadata")
			continue
		}

		ts := make([]string, 0, len(t))
		for m := range t {
			ts = append(ts, m)
		}
		slices.Sort(ts)

		cveKey := strings.Join(ts, "_")

		rec, ok := erCache[cveKey]
		if !ok {
			var err error
			rec, err = g.GetEnrichment(ctx, ts)
			if err != nil {
				return "", nil, err
			}
			erCache[cveKey] = rec
		}

		zlog.Debug(ctx).Int("count", len(rec)).Msg("found records")

		// Skip if no enrichment records are found
		if len(rec) == 0 {
			zlog.Debug(ctx).Strs("cve", ts).Msg("no enrichment records found for CVEs")
			continue
		}

		for _, r := range rec {
			m[id] = append(m[id], r.Enrichment)
		}
	}

	if len(m) == 0 {
		return Type, nil, nil
	}

	b, err := json.Marshal(m)
	if err != nil {
		return Type, nil, err
	}
	return Type, []json.RawMessage{b}, nil
}
