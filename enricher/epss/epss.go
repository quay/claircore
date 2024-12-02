package epss

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/enricher"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
	"github.com/quay/zlog"
)

var (
	_ driver.Enricher          = (*Enricher)(nil)
	_ driver.EnrichmentUpdater = (*Enricher)(nil)
)

type EPSSItem struct {
	ModelVersion string  `json:"modelVersion"`
	Date         string  `json:"date"`
	CVE          string  `json:"cve"`
	EPSS         float64 `json:"epss"`
	Percentile   float64 `json:"percentile"`
}

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.vulnerability; enricher=clair.epss schema=https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v3.x.json`

	// DefaultFeed is the default place to look for EPSS feeds.
	// epss_scores-YYYY-MM-DD.csv.gz needs to be specified to get all data
	DefaultFeed = `https://epss.cyentia.com/`

	// epssName is the name of the enricher
	epssName = `clair.epss`
)

func init() {
	var err error
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
	e.feedPath = currentFeedURL()
	if f == nil {
		zlog.Debug(ctx).Msg("No configuration provided; proceeding with default settings")
		return nil
	}
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.FeedRoot != nil {
		// validate the URL format
		if _, err := url.Parse(*cfg.FeedRoot); err != nil {
			return fmt.Errorf("invalid URL format for FeedRoot: %w", err)
		}

		// only .gz file is supported
		if strings.HasSuffix(*cfg.FeedRoot, ".gz") {
			//overwrite feedPath is cfg provides another feed path
			e.feedPath = *cfg.FeedRoot
		} else {
			return fmt.Errorf("invalid feed root: expected a '.gz' file, but got '%q'", *cfg.FeedRoot)
		}
	}

	return nil
}

// FetchEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) FetchEnrichment(ctx context.Context, prevFingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/FetchEnrichment")

	if e.feedPath == "" || !strings.HasSuffix(e.feedPath, ".gz") {
		return nil, "", fmt.Errorf("invalid feed path: %q must be non-empty and end with '.gz'", e.feedPath)
	}

	out, err := tmp.NewFile("", "epss.")
	if err != nil {
		return nil, "", err
	}
	var success bool
	defer func() {
		if !success {
			if err := out.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close spool")
			}
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.feedPath, nil)
	if err != nil {
		return nil, "", fmt.Errorf("unable to create request for %s: %w", e.feedPath, err)
	}

	resp, err := e.c.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("unable to fetch file from %s: %w", e.feedPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unable to fetch file: received status %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		return nil, "", fmt.Errorf("ETag not found in response headers")
	}

	newFingerprint := driver.Fingerprint(etag)

	if prevFingerprint == newFingerprint {
		zlog.Info(ctx).Str("fingerprint", string(newFingerprint)).Msg("file unchanged; skipping processing")
		return nil, prevFingerprint, nil
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("unable to decompress file: %w", err)
	}
	defer gzipReader.Close()

	csvReader := csv.NewReader(gzipReader)
	csvReader.FieldsPerRecord = -1 // Allow variable-length fields

	// assume metadata is always in the first line
	record, err := csvReader.Read()
	if err != nil {
		return nil, "", fmt.Errorf("unable to read metadata line: %w", err)
	}

	var modelVersion, date string
	for _, field := range record {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(field, "#") {
			field = strings.TrimPrefix(field, "#")
		}
		kv := strings.SplitN(field, ":", 2)
		if len(kv) == 2 {
			switch strings.TrimSpace(kv[0]) {
			case "model_version":
				modelVersion = strings.TrimSpace(kv[1])
			case "score_date":
				date = strings.TrimSpace(kv[1])
			}
		}
	}

	if modelVersion == "" || date == "" {
		return nil, "", fmt.Errorf("missing metadata fields in record: %v", record)
	}

	csvReader.Comment = '#' // Ignore subsequent comment lines

	record, err = csvReader.Read()
	if err != nil {
		return nil, "", fmt.Errorf("unable to read header line: %w", err)
	}
	if len(record) < 3 || record[0] != "cve" || record[1] != "epss" || record[2] != "percentile" {
		return nil, "", fmt.Errorf("unexpected CSV headers: %v", record)
	}
	headers := record

	enc := json.NewEncoder(out)
	totalCVEs := 0

	for {
		record, err = csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("unable to read line in CSV: %w", err)
		}

		if len(record) != len(headers) {
			zlog.Warn(ctx).Str("record", fmt.Sprintf("%v", record)).Msg("skipping record with mismatched fields")
			continue
		}

		r, err := newItemFeed(record, headers, modelVersion, date)
		if err != nil {
			zlog.Warn(ctx).Str("record", fmt.Sprintf("%v", record)).Msg("skipping invalid record")
			continue
		}

		if err = enc.Encode(&r); err != nil {
			return nil, "", fmt.Errorf("unable to write JSON line to file: %w", err)
		}
		totalCVEs++
	}

	zlog.Info(ctx).Int("totalCVEs", totalCVEs).Msg("processed CVEs")
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return nil, newFingerprint, fmt.Errorf("unable to reset file pointer: %w", err)
	}
	success = true

	return out, newFingerprint, nil
}

// ParseEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) ParseEnrichment(ctx context.Context, rc io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/ParseEnrichment")

	defer func() {
		_ = rc.Close()
	}()

	dec := json.NewDecoder(rc)
	ret := make([]driver.EnrichmentRecord, 0, 250_000)
	var err error

	for {
		var record driver.EnrichmentRecord
		if err = dec.Decode(&record); err != nil {
			break
		}
		ret = append(ret, record)
	}

	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("decoded enrichments")

	if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("error decoding enrichment records: %w", err)
	}

	return ret, nil
}

func (*Enricher) Name() string {
	return epssName
}

func currentFeedURL() string {
	currentDate := time.Now()
	formattedDate := currentDate.Format("2006-01-02")
	filePath := fmt.Sprintf("epss_scores-%s.csv.gz", formattedDate)

	feedURL, err := url.Parse(DefaultFeed)
	if err != nil {
		panic(fmt.Errorf("invalid default feed URL: %w", err))
	}

	feedURL.Path = path.Join(feedURL.Path, filePath)
	return feedURL.String()
}

func (e *Enricher) Enrich(ctx context.Context, g driver.EnrichmentGetter, r *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/Enrich")
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

		zlog.Debug(ctx).Int("count", len(rec)).Msg("found records")

		// Skip if no enrichment records are found
		if len(rec) == 0 {
			zlog.Debug(ctx).Strs("cve", ts).Msg("no enrichment records found for CVEs")
			continue
		}

		for _, r := range rec {
			if _, exists := m[id]; !exists {
				m[id] = []json.RawMessage{}
			}
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

func newItemFeed(record []string, headers []string, modelVersion string, scoreDate string) (driver.EnrichmentRecord, error) {
	if len(record) != len(headers) {
		return driver.EnrichmentRecord{}, fmt.Errorf("record and headers length mismatch")
	}

	var item EPSSItem
	for i, value := range record {
		switch headers[i] {
		case "cve":
			item.CVE = value
		case "epss":
			if f, err := strconv.ParseFloat(value, 64); err == nil {
				item.EPSS = f
			} else {
				return driver.EnrichmentRecord{}, fmt.Errorf("invalid float for epss: %w", err)
			}
		case "percentile":
			if f, err := strconv.ParseFloat(value, 64); err == nil {
				item.Percentile = f
			} else {
				return driver.EnrichmentRecord{}, fmt.Errorf("invalid float for percentile: %w", err)
			}
		}
	}

	item.ModelVersion = modelVersion
	item.Date = scoreDate

	enrichment, err := json.Marshal(item)
	if err != nil {
		return driver.EnrichmentRecord{}, fmt.Errorf("unable to encode enrichment: %w", err)
	}

	r := driver.EnrichmentRecord{
		Tags:       []string{item.CVE}, // CVE field should be set
		Enrichment: enrichment,
	}

	return r, nil
}
