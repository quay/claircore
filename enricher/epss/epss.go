package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
	"github.com/quay/zlog"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	_ driver.Enricher          = (*Enricher)(nil)
	_ driver.EnrichmentUpdater = (*Enricher)(nil)

	defaultFeed *url.URL
)

// This is a slightly more relaxed version of the validation pattern in the NVD
// JSON schema: https://csrc.nist.gov/schema/nvd/feed/1.1/CVE_JSON_4.0_min_1.1.schema
//
// It allows for "CVE" to be case insensitive and for dashes and underscores
// between the different segments.
var cveRegexp = regexp.MustCompile(`(?i:cve)[-_][0-9]{4}[-_][0-9]{4,}`)

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.vulnerability; enricher=clair.epss schema=https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v3.x.json`

	// DefaultFeeds is the default place to look for EPSS feeds.
	// epss_scores-YYYY-MM-DD.csv.gz needs to be specified to get all data
	DefaultFeeds = `https://epss.cyentia.com/`

	// epssName is the name of the enricher
	epssName = `clair.epss`
)

func init() {
	var err error
	defaultFeed, err = url.Parse(DefaultFeeds)
	if err != nil {
		panic(err)
	}
}

// Enricher provides EPSS data as enrichments to a VulnerabilityReport.
//
// Configure must be called before any other methods.
type Enricher struct {
	driver.NoopUpdater
	c        *http.Client
	feed     *url.URL
	feedPath string
}

// Config is the configuration for Enricher.
type Config struct {
	FeedRoot *string `json:"feed_root" yaml:"feed_root"`
}

func (e *Enricher) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/Configure")
	var cfg Config
	e.c = c

	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.FeedRoot != nil {
		// validate the URL format
		if _, err := url.Parse(*cfg.FeedRoot); err != nil {
			return fmt.Errorf("invalid URL format for FeedRoot: %w", err)
		}

		// Check for a .gz file
		if strings.HasSuffix(*cfg.FeedRoot, ".gz") {
			e.feedPath = *cfg.FeedRoot
		} else {
			e.sourceURL() // Fallback to the default source URL if not a .gz file
		}
	} else {
		e.sourceURL()
	}

	return nil
}

func (e *Enricher) FetchEnrichment(ctx context.Context, _ driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/FetchEnrichment")
	newUUID := uuid.New()
	hint := driver.Fingerprint(newUUID.String())
	zlog.Info(ctx).Str("hint", string(hint)).Msg("starting fetch")

	out, err := tmp.NewFile("", "enricher.epss.*.json")
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

	if e.feedPath == "" || !strings.HasSuffix(e.feedPath, ".gz") {
		e.sourceURL()
	}

	resp, err := http.Get(e.feedPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch file from %s: %w", e.feedPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to fetch file: received status %d", resp.StatusCode)
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decompress file: %w", err)
	}
	defer gzipReader.Close()

	scanner := bufio.NewScanner(gzipReader)
	var headers []string
	enc := json.NewEncoder(out)
	totalCVEs := 0

	// get headers
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue // Skip comment or empty lines
		}
		headers = strings.Split(line, ",")
		break
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		record := strings.Split(line, ",")
		if len(record) != len(headers) {
			zlog.Warn(ctx).Str("line", line).Msg("skipping line with mismatched fields")
			continue // Skip lines with mismatched number of fields
		}

		r, err := newItemFeed(record, headers)
		if err != nil {
			return nil, "", err
		}

		if err = enc.Encode(&r); err != nil {
			return nil, "", fmt.Errorf("failed to write JSON line to file: %w", err)
		}
		totalCVEs++
	}

	if err := scanner.Err(); err != nil {
		return nil, "", fmt.Errorf("error reading file: %w", err)
	}

	zlog.Info(ctx).Int("totalCVEs", totalCVEs).Msg("processed CVEs")
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return nil, hint, fmt.Errorf("unable to reset file pointer: %w", err)
	}
	success = true

	return out, hint, nil
}

// ParseEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) ParseEnrichment(ctx context.Context, rc io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/ParseEnrichment")
	// Our Fetch method actually has all the smarts w/r/t to constructing the
	// records, so this is just decoding in a loop.
	defer func() {
		_ = rc.Close()
	}()
	var err error
	dec := json.NewDecoder(rc)
	ret := make([]driver.EnrichmentRecord, 0, 250_000) // Wild guess at initial capacity.
	// This is going to allocate like mad, hold onto your butts.
	for err == nil {
		ret = append(ret, driver.EnrichmentRecord{})
		err = dec.Decode(&ret[len(ret)-1])
	}
	zlog.Debug(ctx).
		Int("count", len(ret)-1).
		Msg("decoded enrichments")
	if !errors.Is(err, io.EOF) {
		return nil, err
	}
	return ret, nil
}

func (*Enricher) Name() string {
	return epssName
}

func (e *Enricher) sourceURL() {
	currentDate := time.Now()
	formattedDate := currentDate.Format("2006-01-02")
	filePath := fmt.Sprintf("epss_scores-%s.csv.gz", formattedDate)
	e.feedPath = path.Join(DefaultFeeds, filePath)
}

func (e *Enricher) Enrich(ctx context.Context, g driver.EnrichmentGetter, r *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/Enrich")

	// We return any CVSS blobs for CVEs mentioned in the free-form parts of the
	// vulnerability.
	m := make(map[string][]json.RawMessage)

	erCache := make(map[string][]driver.EnrichmentRecord)
	for id, v := range r.Vulnerabilities {
		t := make(map[string]struct{})
		ctx := zlog.ContextWithValues(ctx,
			"vuln", v.Name)
		for _, elem := range []string{
			v.Description,
			v.Name,
			v.Links,
		} {
			for _, m := range cveRegexp.FindAllString(elem, -1) {
				t[m] = struct{}{}
			}
		}
		if len(t) == 0 {
			continue
		}
		ts := make([]string, 0, len(t))
		for m := range t {
			ts = append(ts, m)
		}
		zlog.Debug(ctx).
			Strs("cve", ts).
			Msg("found CVEs")

		sort.Strings(ts)
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
		zlog.Debug(ctx).
			Int("count", len(rec)).
			Msg("found records")
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

func newItemFeed(record []string, headers []string) (driver.EnrichmentRecord, error) {
	item := make(map[string]string)
	for i, value := range record {
		item[headers[i]] = value
	}

	enrichment, err := json.Marshal(item)
	if err != nil {
		return driver.EnrichmentRecord{}, fmt.Errorf("failed to encode enrichment: %w", err)
	}

	r := driver.EnrichmentRecord{
		Tags:       []string{item["cve"]},
		Enrichment: enrichment,
	}

	return r, nil
}
