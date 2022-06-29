package debian

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/claircore/pkg/tmp"
)

const (
	defaultMirror  = `https://deb.debian.org/`
	defaultArchive = `http://archive.debian.org/`
	defaultOVAL    = `https://www.debian.org/security/oval/`
)

var (
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.Updater           = (*updater)(nil)
	_ driver.Configurable      = (*updater)(nil)
)

// Factory creates Updaters for all Debian distributions that exist on either
// the archive or mirror, and have an OVAL database.
//
// [Configure] must be called before [UpdaterSet].
type Factory struct {
	c       *http.Client
	mirror  *url.URL
	archive *url.URL
	oval    *url.URL
}

// NewFactory constructs a Factory.
//
// [Configure] must be called before [UpdaterSet].
func NewFactory(ctx context.Context) (*Factory, error) {
	f := &Factory{}
	return f, nil
}

// Configure implements [driver.Configurable].
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return fmt.Errorf("debian: factory configuration error: %w", err)
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

	u, err = url.Parse(defaultArchive)
	if cfg.ArchiveURL != "" {
		u, err = url.Parse(cfg.ArchiveURL)
	}
	if err != nil {
		return fmt.Errorf("debian: bad archive URL: %w", err)
	}
	f.archive, err = u.Parse("debian/")
	if err != nil {
		return fmt.Errorf("debian: bad archive URL: %w", err)
	}

	f.oval, err = url.Parse(defaultOVAL)
	if cfg.OVALURL != "" {
		f.oval, err = url.Parse(cfg.OVALURL)
	}
	if err != nil {
		return fmt.Errorf("debian: bad OVAL URL: %w", err)
	}

	return nil
}

// FactoryConfig is the configuration honored by the Factory.
//
// All URLs need trailing slashes.
//
// The "archive" and "mirror" URLs expect to find HTML at "dists/" formatted like
// the HTML from the Debian project (that is to say, HTML containing relative links
// to distribution directories).
//
// The "OVAL" URL expects to have OVAL XML documents named "oval-definitions-${name}.xml",
// where "name" is the release's code name (e.g. "wheezy", "buster").
type FactoryConfig struct {
	// ArchiveURL is a URL to a Debian archive.
	ArchiveURL string `json:"archive_url" yaml:"archive_url"`
	// MirrorURL is a URL to an active Debian mirror.
	MirrorURL string `json:"mirror_url" yaml:"mirror_url"`
	// OVALURL is a URL to a collection of OVAL XML documents.
	OVALURL string `json:"oval_url" yaml:"oval_url"`
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

	// Collect updaters via a map, so that any release that's partially archived
	// gets used via the mirror URLs. When this was written, "jessie" was in this state.
	us := make(map[string]*updater)
	for _, u := range []*url.URL{f.archive, f.mirror} {

		ds, err := f.findReleases(ctx, u)
		if err != nil {
			return s, fmt.Errorf("debian: examining remote: %w", err)
		}
		for _, d := range ds {
			ovalURL, err := f.oval.Parse(fmt.Sprintf("oval-definitions-%s.xml", d.VersionCodeName))
			if err != nil {
				return s, fmt.Errorf("debian: unable to construct OVAL URL: %w", err)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, ovalURL.String(), nil)
			if err != nil {
				return s, fmt.Errorf("debian: unable to construct OVAL HEAD request: %w", err)
			}
			res, err := f.c.Do(req)
			if err != nil {
				return s, fmt.Errorf("debian: unable to do OVAL HEAD request: %w", err)
			}
			res.Body.Close()
			switch res.StatusCode {
			case http.StatusOK:
			default:
				continue
			}
			src, err := u.Parse(path.Join("dists", d.VersionCodeName) + "/")
			if err != nil {
				return s, fmt.Errorf("debian: unable to construct source URL: %w", err)
			}

			us[d.VersionCodeName] = &updater{
				url:   ovalURL.String(),
				dists: src.String(),
				name:  d.VersionCodeName,
			}
		}
	}
	for _, u := range us {
		if err := s.Add(u); err != nil {
			return s, fmt.Errorf("debian: unable to add updater: %w", err)
		}
	}

	return s, nil
}

// FindReleases is split out as a method to make it easier to examine the mirror and the archive.
func (f *Factory) findReleases(ctx context.Context, u *url.URL) ([]*claircore.Distribution, error) {
	dir, err := u.Parse("dists/")
	if err != nil {
		return nil, fmt.Errorf("debian: unable to construct URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dir.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("debian: unable to construct request: %w", err)
	}
	res, err := f.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("debian: unable to do request: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("debian: unexpected status fetching %q: %s", dir.String(), res.Status)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		return nil, fmt.Errorf("debian: unable to read dists listing: %w", err)
	}
	ms := linkRegexp.FindAllStringSubmatch(buf.String(), -1)

	var todos []*claircore.Distribution
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
			zlog.Info(ctx).
				Err(err).
				Stringer("context", dir).
				Str("target", path.Join(dist, `Release`)).
				Msg("unable to construct URL")
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rf.String(), nil)
		if err != nil {
			zlog.Info(ctx).
				Err(err).
				Stringer("url", rf).
				Msg("unable to construct request")
			continue
		}
		req.Header.Set("range", "bytes=0-512")
		res, err := f.c.Do(req)
		if err != nil {
			zlog.Info(ctx).
				Err(err).
				Stringer("url", rf).
				Msg("unable to do request")
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
			zlog.Info(ctx).
				Str("status", res.Status).
				Stringer("url", rf).
				Msg("unexpected response")
			continue
		}
		tp := textproto.NewReader(bufio.NewReader(io.MultiReader(&buf, bytes.NewReader([]byte("\r\n\r\n")))))
		h, err := tp.ReadMIMEHeader()
		if err != nil {
			zlog.Info(ctx).Err(err).Msg("unable to read MIME-ish headers")
			continue
		}
		sv := h.Get("Version")
		if sv == "" {
			zlog.Debug(ctx).Str("dist", dist).Msg("no version assigned, skipping")
			continue
		}
		vs := strings.Split(sv, ".")
		if len(vs) == 1 {
			zlog.Debug(ctx).Str("dist", dist).Msg("no version assigned, skipping")
			continue
		}
		ver, err := strconv.ParseInt(vs[0], 10, 32)
		if err != nil {
			zlog.Info(ctx).Err(err).Msg("unable to parse version")
			continue
		}

		todos = append(todos, mkDist(dist, int(ver)))
	}

	return todos, nil
}

// Updater implements [driver.updater].
type updater struct {
	// the url to fetch the OVAL db from
	url   string
	dists string
	// the release name as described by os-release "VERSION_CODENAME"
	name string

	c  *http.Client
	sm *sourcesMap
}

// UpdaterConfig is the configuration for the updater.
//
// By convention, this is in a map called "debian/updater/${RELEASE}", e.g.
// "debian/updater/buster".
type UpdaterConfig struct {
	OVALURL  string `json:"url" yaml:"url"`
	DistsURL string `json:"dists_url" yaml:"dists_url"`
}

// Name implements [driver.Updater].
func (u *updater) Name() string {
	return path.Join(`debian`, `updater`, u.name)
}

// Configure implements [driver.Configurable].
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "debian/Updater.Configure")
	u.c = c
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return nil
	}
	if cfg.OVALURL != "" {
		u.url = cfg.OVALURL
		zlog.Info(ctx).
			Msg("configured database URL")
	}
	if cfg.DistsURL != "" {
		u.dists = cfg.DistsURL
		zlog.Info(ctx).
			Msg("configured dists URL")
	}

	src, err := url.Parse(u.dists)
	if err != nil {
		return fmt.Errorf("debian: unable to parse dists URL: %w", err)
	}
	u.sm = newSourcesMap(src, u.c)

	return nil
}

// Fetch implements [driver.Fetcher].
func (u *updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "debian/Updater.Fetch",
		"release", u.name,
		"database", u.url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request")
	}
	if fingerprint != "" {
		req.Header.Set("if-none-match", string(fingerprint))
	}

	// fetch OVAL xml database
	resp, err := u.c.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to retrieve OVAL database: %v", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if fingerprint == "" || string(fingerprint) != resp.Header.Get("etag") {
			zlog.Info(ctx).Msg("fetching latest oval database")
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil, fingerprint, driver.Unchanged
	default:
		return nil, "", fmt.Errorf("unexpected response: %v", resp.Status)
	}

	fp := resp.Header.Get("etag")
	f, err := tmp.NewFile("", "debian.")
	if err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("failed to read http body: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("failed to seek body: %v", err)
	}
	zlog.Info(ctx).Msg("fetched latest oval database successfully")

	err = u.sm.Update(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("could not update source to binary map: %w", err)
	}
	zlog.Info(ctx).Msg("updated the debian source to binary map successfully")

	return f, driver.Fingerprint(fp), err
}

// Parse implements [driver.Parser].
func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "debian/Updater.Parse",
		"release", u.name,
	)
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("debian: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")

	sourcesMapFunc := func(_ oval.Definition, name *oval.DpkgName) []string {
		return u.sm.Get(name.Body)
	}

	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		vs := []*claircore.Vulnerability{}
		d, err := getDist(u.name)
		if err != nil {
			return nil, err
		}
		v := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			NormalizedSeverity: claircore.Unknown,
			Dist:               d,
		}
		vs = append(vs, v)
		return vs, nil
	}
	vulns, err := ovalutil.DpkgDefsToVulns(ctx, &root, protoVulns, sourcesMapFunc)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}
