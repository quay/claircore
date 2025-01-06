// Package epss provides a epss enricher.
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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/enricher"
	"github.com/quay/claircore/internal/httputil"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	_ driver.Enricher          = (*Enricher)(nil)
	_ driver.EnrichmentUpdater = (*Enricher)(nil)
)

// EPSSItem represents a single entry in the EPSS feed, containing information
// about a CVE's Exploit Prediction Scoring System (EPSS) score and percentile.
type EPSSItem struct {
	ModelVersion string  `json:"modelVersion"`
	Date         string  `json:"date"`
	CVE          string  `json:"cve"`
	EPSS         float64 `json:"epss"`
	Percentile   float64 `json:"percentile"`
}

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.vulnerability; enricher=clair.epss schema=none`

	// DefaultBaseURL is the default place to look for EPSS feeds.
	// epss_scores-YYYY-MM-DD.csv.gz needs to be specified to get all data
	DefaultBaseURL = `https://epss.cyentia.com/`

	// epssName is the name of the enricher
	epssName = `clair.epss`
)

// Enricher provides EPSS data as enrichments to a VulnerabilityReport.
//
// Configure must be called before any other methods.
type Enricher struct {
	driver.NoopUpdater
	c        *http.Client
	baseURL  *url.URL
	feedPath string
}

// Config is the configuration for Enricher.
type Config struct {
	URL *string `json:"url" yaml:"url"`
}

// NewFactory creates a Factory for the EPSS enricher.
func NewFactory() driver.UpdaterSetFactory {
	set := driver.NewUpdaterSet()
	_ = set.Add(&Enricher{})
	return driver.StaticSet(set)
}

func (e *Enricher) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/Configure")
	var cfg Config
	e.c = c
	e.feedPath = currentFeedURL()
	if f == nil {
		return fmt.Errorf("configuration is nil")
	}
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != nil {
		// validate the URL format
		if _, err := url.Parse(*cfg.URL); err != nil {
			return fmt.Errorf("invalid URL format for URL: %w", err)
		}

		// only .gz file is supported
		if strings.HasSuffix(*cfg.URL, ".gz") {
			//overwrite feedPath is cfg provides another baseURL path
			e.feedPath = *cfg.URL
		} else {
			return fmt.Errorf("invalid baseURL root: expected a '.gz' file, but got '%q'", *cfg.URL)
		}
	}

	return nil
}

// FetchEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) FetchEnrichment(ctx context.Context, prevFingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/epss/Enricher/FetchEnrichment")

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

	if err = httputil.CheckResponse(resp, http.StatusOK); err != nil {
		return nil, "", fmt.Errorf("unable to fetch file: %w", err)
	}

	var newFingerprint driver.Fingerprint
	if etag := resp.Header.Get("etag"); etag != "" {
		newFingerprint = driver.Fingerprint(etag)
		if prevFingerprint == newFingerprint {
			zlog.Info(ctx).Str("fingerprint", string(newFingerprint)).Msg("file unchanged; skipping processing")
			return nil, prevFingerprint, nil
		}
		newFingerprint = driver.Fingerprint(etag)
	}
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("unable to decompress file: %w", err)
	}
	defer gzipReader.Close()

	csvReader := csv.NewReader(gzipReader)
	csvReader.FieldsPerRecord = 2

	// assume metadata is always in the first line
	record, err := csvReader.Read()
	if err != nil {
		return nil, "", fmt.Errorf("unable to read metadata line: %w", err)
	}

	var modelVersion, date string
	for _, field := range record {
		field = strings.TrimPrefix(strings.TrimSpace(field), "#")
		key, value, found := strings.Cut(field, ":")
		if !found {
			return nil, "", fmt.Errorf("unexpected metadata field format: %q", field)
		}
		switch key {
		case "model_version":
			modelVersion = value
		case "score_date":
			date = value
		}
	}

	if modelVersion == "" || date == "" {
		return nil, "", fmt.Errorf("missing metadata fields in record: %v", record)
	}
	csvReader.Comment = '#'

	csvReader.FieldsPerRecord = 3 // Expect exactly 3 fields per record

	// Read and validate header line
	record, err = csvReader.Read()
	if err != nil {
		return nil, "", fmt.Errorf("unable to read header line: %w", err)
	}

	expectedHeaders := []string{"cve", "epss", "percentile"}
	if !slices.Equal(record, expectedHeaders) {
		return nil, "", fmt.Errorf("unexpected CSV headers: %v", record)
	}

	enc := json.NewEncoder(out)
	totalCVEs := 0

	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("unable to read line in CSV: %w", err)
		}

		r, err := newItemFeed(record, modelVersion, date)
		if err != nil {
			zlog.Warn(ctx).Err(err).Msg("skipping invalid record")
			continue
		}

		if err := enc.Encode(&r); err != nil {
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

	defer rc.Close()

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
	yesterday := time.Now().AddDate(0, 0, -1) // Get yesterday's date
	formattedDate := yesterday.Format("2006-01-02")
	filePath := fmt.Sprintf("epss_scores-%s.csv.gz", formattedDate)

	feedURL, err := url.Parse(DefaultBaseURL)
	if err != nil {
		panic(fmt.Errorf("invalid default baseURL URL: %w", err))
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

func newItemFeed(record []string, modelVersion string, scoreDate string) (driver.EnrichmentRecord, error) {
	// Validate the record has the expected length
	if len(record) != 3 {
		return driver.EnrichmentRecord{}, fmt.Errorf("unexpected record length: %d", len(record))
	}

	var item EPSSItem
	item.CVE = record[0]

	if f, err := strconv.ParseFloat(record[1], 64); err == nil {
		item.EPSS = f
	} else {
		return driver.EnrichmentRecord{}, fmt.Errorf("invalid float for epss: %w", err)
	}

	if f, err := strconv.ParseFloat(record[2], 64); err == nil {
		item.Percentile = f
	} else {
		return driver.EnrichmentRecord{}, fmt.Errorf("invalid float for percentile: %w", err)
	}

	item.ModelVersion = modelVersion
	item.Date = scoreDate

	enrichment, err := json.Marshal(item)
	if err != nil {
		return driver.EnrichmentRecord{}, fmt.Errorf("unable to encode enrichment: %w", err)
	}

	r := driver.EnrichmentRecord{
		Tags:       []string{item.CVE},
		Enrichment: enrichment,
	}

	return r, nil
}
