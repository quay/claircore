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
	"strconv"
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
	if f == nil {
		zlog.Warn(ctx).Msg("No configuration provided; proceeding with default settings")
		e.sourceURL()
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
	var modelVersion, date string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// assume metadata is always available at first comment of the file
		if strings.HasPrefix(line, "#") && date == "" && modelVersion == "" {
			modelVersion, date = parseMetadata(line)
			zlog.Info(ctx).
				Str("modelVersion", modelVersion).
				Str("scoreDate", date).
				Msg("parsed metadata")
			continue
		}
		if headers == nil {
			headers = strings.Split(line, ",")
			continue
		}

		record := strings.Split(line, ",")
		if len(record) != len(headers) {
			zlog.Warn(ctx).Str("line", line).Msg("skipping line with mismatched fields")
			continue
		}

		r, err := newItemFeed(record, headers, modelVersion, date)
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

	feedURL, err := url.Parse(DefaultFeeds)
	if err != nil {
		panic(fmt.Errorf("invalid default feed URL: %w", err))
	}

	feedURL.Path = path.Join(feedURL.Path, filePath)
	e.feedPath = feedURL.String()
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

			matches := cveRegexp.FindAllString(elem, -1)
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
		zlog.Debug(ctx).Str("cve_key", cveKey).Strs("cve", ts).Msg("generated CVE cache key")

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
	item := make(map[string]interface{}) // Use interface{} to allow mixed types
	for i, value := range record {
		// epss details are numeric values
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			item[headers[i]] = f
		} else {
			item[headers[i]] = value
		}
	}

	if modelVersion != "" {
		item["modelVersion"] = modelVersion
	}
	if scoreDate != "" {
		item["date"] = scoreDate
	}

	enrichment, err := json.Marshal(item)
	if err != nil {
		return driver.EnrichmentRecord{}, fmt.Errorf("failed to encode enrichment: %w", err)
	}

	r := driver.EnrichmentRecord{
		Tags:       []string{item["cve"].(string)}, // Ensure the "cve" field is a string
		Enrichment: enrichment,
	}

	return r, nil
}

func parseMetadata(line string) (modelVersion string, scoreDate string) {
	// Set default values
	modelVersion = "N/A"
	scoreDate = "0001-01-01"

	trimmedLine := strings.TrimPrefix(line, "#")
	parts := strings.Split(trimmedLine, ",")
	for _, part := range parts {
		keyValue := strings.SplitN(part, ":", 2)
		if len(keyValue) == 2 {
			key := strings.TrimSpace(keyValue[0])
			value := strings.TrimSpace(keyValue[1])

			switch key {
			case "score_date":
				scoreDate = value
			case "model_version":
				modelVersion = value
			}
		}
	}

	return modelVersion, scoreDate
}
