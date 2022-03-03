package debian

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

func init() {
	pkgVersionRegex = regexp.MustCompile(PkgNameVersion)
}

const (
	OVALTemplate   = "https://www.debian.org/security/oval/oval-definitions-%s.xml"
	PkgNameVersion = `([^\s]+) DPKG is earlier than (.+)`
)

var pkgVersionRegex *regexp.Regexp

// pkgInfo is a helper struct when parsing Criterias
type pkgInfo struct {
	name    string
	version string
}

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as an Updater.
type Updater struct {
	// the url to fetch the OVAL db from
	url string
	// the release name as described by os-release "VERSION_CODENAME"
	release Release
	c       *http.Client
	sm      *SourcesMap
}

// UpdaterConfig is the configuration for the updater.
//
// By convention, this is in a map called "debian-${RELEASE}-updater", e.g.
// "debian-buster-updater".
type UpdaterConfig struct {
	URL string `json:"url" yaml:"url"`
}

func NewUpdater(release Release) *Updater {
	url := fmt.Sprintf(OVALTemplate, release)

	c := http.DefaultClient // TODO(hank) Remove DefaultClient
	return &Updater{
		url:     url,
		release: release,
		c:       c,
		sm:      NewSourcesMap(release, c),
	}
}

func (u *Updater) Name() string {
	return fmt.Sprintf(`debian-%s-updater`, string(u.release))
}

// Configure implements driver.Configurable.
func (u *Updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "debian/Updater.Configure")
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return nil
	}
	if cfg.URL != "" {
		u.url = cfg.URL
		zlog.Info(ctx).
			Msg("configured database URL")
	}
	u.c = c
	zlog.Info(ctx).
		Msg("configured HTTP client")

	return nil
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "debian/Updater.Fetch",
		"release", string(u.release),
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
