// Package cvss provides a cvss enricher.
package cvss

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
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
	Type = `message/vnd.clair.map.vulnerability; enricher=clair.cvss schema=https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v3.x.json`
	// DefaultFeeds is the default place to look for CVE feeds.
	//
	// The enricher expects the structure to mirror that found here: files
	// organized by year, prefixed with `nvdcve-1.1-` and with `.meta` and
	// `.json.gz` extensions.
	DefaultFeeds = `https://nvd.nist.gov/feeds/json/cve/1.1/`

	// This appears above and must be the same.
	name = `clair.cvss`

	// First year for the yearly CVE feeds: https://nvd.nist.gov/vuln/data-feeds
	firstYear = 2002
)

func init() {
	var err error
	defaultFeed, err = url.Parse(DefaultFeeds)
	if err != nil {
		panic(err)
	}
}

// Enricher provides CVSS data as enrichments to a VulnerabilityReport.
//
// Configure must be called before any other methods.
type Enricher struct {
	driver.NoopUpdater
	c    *http.Client
	feed *url.URL
}

// Config is the configuration for Enricher.
type Config struct {
	FeedRoot *string `json:"feed_root" yaml:"feed_root"`
}

// Configure implements driver.Configurable.
func (e *Enricher) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg Config
	e.c = c
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.FeedRoot != nil {
		if !strings.HasSuffix(*cfg.FeedRoot, "/") {
			return fmt.Errorf("URL missing trailing slash: %q", *cfg.FeedRoot)
		}
		u, err := url.Parse(*cfg.FeedRoot)
		if err != nil {
			return err
		}
		e.feed = u
	} else {
		var err error
		e.feed, err = defaultFeed.Parse(".")
		if err != nil {
			panic(fmt.Errorf("programmer error: %w", err))
		}
	}
	return nil
}

func metafileURL(root *url.URL, yr int) (*url.URL, error) {
	return root.Parse(fmt.Sprintf("nvdcve-1.1-%d.meta", yr))
}

func gzURL(root *url.URL, yr int) (*url.URL, error) {
	return root.Parse(fmt.Sprintf("nvdcve-1.1-%d.json.gz", yr))
}

// Name implements driver.Enricher and driver.EnrichmentUpdater.
func (*Enricher) Name() string { return name }

// FetchEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) FetchEnrichment(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/cvss/Enricher/FetchEnrichment")

	// year → sha256
	prev := make(map[int]string)
	if err := json.Unmarshal([]byte(hint), &prev); err != nil && hint != "" {
		return nil, driver.Fingerprint(""), err
	}
	cur := make(map[int]string, len(prev))
	yrs := make([]int, 0)

	for y, lim := firstYear, time.Now().Year(); y <= lim; y++ {
		yrs = append(yrs, y)
		u, err := metafileURL(e.feed, y)
		if err != nil {
			return nil, hint, err
		}
		zlog.Debug(ctx).
			Int("year", y).
			Stringer("url", u).
			Msg("fetching meta file")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, hint, err
		}
		res, err := e.c.Do(req)
		if err != nil {
			return nil, hint, err
		}
		var buf bytes.Buffer
		_, err = io.Copy(&buf, res.Body)
		res.Body.Close() // Don't defer because we're in a loop.
		if err != nil {
			return nil, hint, err
		}
		var mf metafile
		if err := mf.Parse(&buf); err != nil {
			return nil, hint, err
		}
		zlog.Debug(ctx).
			Int("year", y).
			Stringer("url", u).
			Time("mod", mf.LastModified).
			Msg("parsed meta file")
		cur[y] = strings.ToUpper(mf.SHA256)
	}

	doFetch := false
	for _, y := range yrs {
		if prev[y] != cur[y] {
			zlog.Info(ctx).
				Int("year", y).
				Msg("change detected")
			doFetch = true
			break
		}
	}
	if !doFetch {
		return nil, hint, driver.Unchanged
	}

	out, err := tmp.NewFile("", "cvss.")
	if err != nil {
		return nil, hint, err
	}
	// Doing this serially is slower, but much less complicated than using an
	// ErrGroup or the like.
	//
	// It may become an issue in 25-30 years.
	for _, y := range yrs {
		u, err := gzURL(e.feed, y)
		if err != nil {
			return nil, hint, fmt.Errorf("bad URL: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, hint, fmt.Errorf("unable to create request: %w", err)
		}
		zlog.Debug(ctx).
			Int("year", y).
			Stringer("url", u).
			Msg("requesting json")
		res, err := e.c.Do(req)
		if err != nil {
			return nil, hint, fmt.Errorf("unable to do request: %w", err)
		}
		gz, err := gzip.NewReader(res.Body)
		if err != nil {
			res.Body.Close()
			return nil, hint, fmt.Errorf("unable to create gzip reader: %w", err)
		}
		f, err := newItemFeed(y, gz)
		gz.Close()
		res.Body.Close()
		if err != nil {
			return nil, hint, fmt.Errorf("unable to process item feed: %w", err)
		}
		if err := f.WriteCVSS(ctx, out); err != nil {
			return nil, hint, fmt.Errorf("unable to write item feed: %w", err)
		}
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return nil, hint, fmt.Errorf("unable to reset item feed: %w", err)
	}

	nh, err := json.Marshal(cur)
	if err != nil {
		panic(fmt.Errorf("unable to serialize new hint: %w", err))
	}
	return out, driver.Fingerprint(nh), nil
}

// ParseEnrichment implements driver.EnrichmentUpdater.
func (e *Enricher) ParseEnrichment(ctx context.Context, rc io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/cvss/Enricher/ParseEnrichment")
	// Our Fetch method actually has all the smarts w/r/t to constructing the
	// records, so this is just decoding in a loop.
	defer rc.Close()
	var err error
	dec := json.NewDecoder(rc)
	ret := make([]driver.EnrichmentRecord, 0, 1024) // Wild guess at initial capacity.
	// This is going to allocate like mad, hold onto your butts.
	for err == nil {
		ret = append(ret, driver.EnrichmentRecord{})
		err = dec.Decode(&ret[len(ret)-1])
	}
	zlog.Debug(ctx).
		Int("count", len(ret)).
		Msg("decoded enrichments")
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return ret, nil
}

// This is a slightly more relaxed version of the validation pattern in the NVD
// JSON schema: https://csrc.nist.gov/schema/nvd/feed/1.1/CVE_JSON_4.0_min_1.1.schema
//
// It allows for "CVE" to be case insensitive and for dashes and underscores
// between the different segments.
var cveRegexp = regexp.MustCompile(`(?i:cve)[-_][0-9]{4}[-_][0-9]{4,}`)

// Enrich implements driver.Enricher.
func (e *Enricher) Enrich(ctx context.Context, g driver.EnrichmentGetter, r *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "enricher/cvss/Enricher/Enrich")

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
