package debian

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

//doc:url updater
const (
	defaultMirror = `https://deb.debian.org/`
	defaultJSON   = `https://security-tracker.debian.org/tracker/data/json`
)

var (
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.Updater           = (*updater)(nil)
	_ driver.Configurable      = (*updater)(nil)
)

// Factory creates Updaters for all Debian distributions that exist
// in the mirror, and have entries in the JSON security tracker.
//
// [Configure] must be called before [UpdaterSet].
type Factory struct {
	c      *http.Client
	mirror *url.URL
	json   *url.URL
}

// NewFactory constructs a Factory.
//
// [Configure] must be called before [UpdaterSet].
func NewFactory(_ context.Context) (*Factory, error) {
	f := &Factory{}
	return f, nil
}

// Configure implements [driver.Configurable].
func (f *Factory) Configure(_ context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return fmt.Errorf("debian: factory configuration error: %w", err)
	}

	if cfg.ArchiveURL != "" || cfg.OVALURL != "" {
		return fmt.Errorf("debian: neither archive_url nor oval_url should be populated anymore; use json_url and mirror_url instead")
	}

	u, err := url.Parse(defaultMirror)
	if cfg.MirrorURL != "" {
		u, err = url.Parse(cfg.MirrorURL)
	}
	if err != nil {
		return fmt.Errorf("debian: bad mirror URL: %w", err)
	}
	f.mirror, err = u.Parse("debian/")
	if err != nil {
		return fmt.Errorf("debian: bad mirror URL: %w", err)
	}

	f.json, err = url.Parse(defaultJSON)
	if cfg.JSONURL != "" {
		f.json, err = url.Parse(cfg.JSONURL)
	}
	if err != nil {
		return fmt.Errorf("debian: bad JSON URL: %w", err)
	}

	return nil
}

// FactoryConfig is the configuration honored by the Factory.
//
// The "mirror" URLs expect to find HTML at "dists/" formatted like
// the HTML from the Debian project (that is to say, HTML containing relative links
// to distribution directories).
//
// The "mirror" URL needs a trailing slash.
//
// The "JSON" URL expects to find a JSON array of packages mapped to related vulnerabilities.
type FactoryConfig struct {
	// ArchiveURL is a URL to a Debian archive.
	//
	// Deprecated: Only MirrorURL should be used.
	ArchiveURL string `json:"archive_url" yaml:"archive_url"`
	MirrorURL  string `json:"mirror_url" yaml:"mirror_url"`
	// OVALURL is a URL to a collection of OVAL XML documents.
	//
	// Deprecated: Use JSONURL instead.
	OVALURL string `json:"oval_url" yaml:"oval_url"`
	// JSONURL is a URL to a JSON vulnerability feed.
	JSONURL string `json:"json_url" yaml:"json_url"`
}

var (
	// LinkRegexp is a bad regexp to extract link targets.
	// This will break if Debian's codenames include a double-quote in the future.
	linkRegexp = regexp.MustCompile(`href="([^"]+)"`)
	// SkipList is a list of strings that, experimentally, indicate the string
	// is not a codename.
	skipList = []string{
		"-", "Debian", "sid", "stable", "testing", "experimental", "README", "updates", "backports",
	}
)

// UpdaterSet implements [driver.UpdaterSetFactory].
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	s := driver.NewUpdaterSet()

	if err := f.findReleases(ctx, f.mirror); err != nil {
		return s, fmt.Errorf("debian: examining remote: %w", err)
	}

	// TODO: Consider returning stub if Last-Modified has not updated.
	u := &updater{
		jsonURL: f.json.String(),
	}

	if err := s.Add(u); err != nil {
		return s, fmt.Errorf("debian: unable to add updater: %w", err)
	}

	return s, nil
}

// FindReleases is split out as a method to make it easier to examine the mirror and the archive.
func (f *Factory) findReleases(ctx context.Context, u *url.URL) error {
	dir, err := u.Parse("dists/")
	if err != nil {
		return fmt.Errorf("debian: unable to construct URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dir.String(), nil)
	if err != nil {
		return fmt.Errorf("debian: unable to construct request: %w", err)
	}
	res, err := f.c.Do(req)
	if err != nil {
		return fmt.Errorf("debian: unable to do request: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return fmt.Errorf("debian: unexpected status fetching %q: %s", dir.String(), res.Status)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		return fmt.Errorf("debian: unable to read dists listing: %w", err)
	}
	ms := linkRegexp.FindAllStringSubmatch(buf.String(), -1)

Listing:
	for _, m := range ms {
		dist := m[1]
		switch {
		case dist == "":
			continue
		case dist[0] == '/', dist[0] == '?':
			continue
		}
		for _, s := range skipList {
			if strings.Contains(dist, s) {
				continue Listing
			}
		}
		dist = strings.Trim(dist, "/")
		rf, err := dir.Parse(path.Join(dist, `Release`))
		if err != nil {
			slog.InfoContext(ctx, "unable to construct URL",
				"reason", err,
				"context", dir,
				"target", path.Join(dist, `Release`))
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rf.String(), nil)
		if err != nil {
			slog.InfoContext(ctx, "unable to construct request",
				"reason", err,
				"url", rf)
			continue
		}
		req.Header.Set("range", "bytes=0-512")
		res, err := f.c.Do(req)
		if err != nil {
			slog.InfoContext(ctx, "unable to do request",
				"reason", err,
				"url", rf)
			continue
		}
		buf.Reset()
		buf.ReadFrom(res.Body)
		res.Body.Close()
		switch res.StatusCode {
		case http.StatusPartialContent, http.StatusOK:
		case http.StatusNotFound: // Probably extremely old, it's fine.
			continue
		default:
			slog.InfoContext(ctx, "unexpected response",
				"status", res.Status,
				"url", rf)
			continue
		}
		tp := textproto.NewReader(bufio.NewReader(io.MultiReader(&buf, bytes.NewReader([]byte("\r\n\r\n")))))
		h, err := tp.ReadMIMEHeader()
		if err != nil {
			slog.InfoContext(ctx, "unable to read MIME-ish headers",
				"reason", err)
			continue
		}
		sv := h.Get("Version")
		if sv == "" {
			slog.DebugContext(ctx, "no version assigned, skipping", "dist", dist)
			continue
		}
		vs := strings.Split(sv, ".")
		if len(vs) == 1 {
			slog.DebugContext(ctx, "no version assigned, skipping", "dist", dist)
			continue
		}
		ver, err := strconv.ParseInt(vs[0], 10, 32)
		if err != nil {
			slog.InfoContext(ctx, "unable to parse version", "reason", err)
			continue
		}

		mkDist(dist, int(ver))
	}

	return nil
}

// Updater implements [driver.updater].
type updater struct {
	// jsonURL is the URL from which to fetch JSON vulnerability data
	jsonURL string

	c *http.Client
}

// UpdaterConfig is the configuration for the updater.
type UpdaterConfig struct {
	// Deprecated: Use JSONURL instead.
	OVALURL string `json:"url" yaml:"url"`
	JSONURL string `json:"json_url" yaml:"json_url"`
	// Deprecated: DistURL and DistsURLs are unused.
	DistsURL  string            `json:"dists_url" yaml:"dists_url"`
	DistsURLs []json.RawMessage `json:"dists_urls" yaml:"dists_urls"`
}

// Name implements [driver.Updater].
func (u *updater) Name() string {
	return "debian/updater"
}

// Configure implements [driver.Configurable].
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	u.c = c
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.DistsURL != "" || cfg.OVALURL != "" {
		slog.ErrorContext(ctx, "configured with deprecated URLs")
		return fmt.Errorf("debian: neither url nor dists_url should be used anymore; use json_url and dists_urls instead")
	}

	if cfg.JSONURL != "" {
		u.jsonURL = cfg.JSONURL
		slog.InfoContext(ctx, "configured JSON database URL")
	}

	return nil
}

// Fetch implements [driver.Fetcher].
func (u *updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := slog.With("database", u.jsonURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.jsonURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request")
	}
	if fingerprint != "" {
		req.Header.Set("If-Modified-Since", string(fingerprint))
	}

	// fetch JSON database
	resp, err := u.c.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve JSON database: %v", err)
	}

	fp := resp.Header.Get("Last-Modified")

	switch resp.StatusCode {
	case http.StatusOK:
		if fingerprint == "" || fp != string(fingerprint) {
			log.InfoContext(ctx, "fetching latest JSON database")
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil, fingerprint, driver.Unchanged
	default:
		return nil, "", fmt.Errorf("unexpected response: %v", resp.Status)
	}

	f, err := tmp.NewFile("", "debian.")
	if err != nil {
		return nil, "", err
	}

	var success bool
	defer func() {
		if !success {
			if err := f.Close(); err != nil {
				log.WarnContext(ctx, "unable to close spool", "reason", err)
			}
		}
	}()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return nil, "", fmt.Errorf("failed to read http body: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, "", fmt.Errorf("failed to seek body: %w", err)
	}
	log.InfoContext(ctx, "fetched latest json database successfully")

	success = true
	return f, driver.Fingerprint(fp), err
}
