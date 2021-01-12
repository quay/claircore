package debian

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

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

var _ driver.Updater = (*Updater)(nil)

// Updater implements the claircore.Updater.Fetcher and claircore.Updater.Parser
// interfaces making it eligible to be used as an Updater.
type Updater struct {
	// the url to fetch the OVAL db from
	url string
	// the release name as described by os-release "VERSION_CODENAME"
	release Release
	c       *http.Client
}

func NewUpdater(release Release) *Updater {
	url := fmt.Sprintf(OVALTemplate, release)

	return &Updater{
		url:     url,
		release: release,
		c:       http.DefaultClient,
	}
}

func (u *Updater) Name() string {
	return fmt.Sprintf(`debian-%s-updater`, string(u.release))
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "debian/Updater.Fetch"),
		label.String("release", string(u.release)),
		label.String("database", u.url))

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
		zlog.Info(ctx).Msg("fetching latest oval database")
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
	return f, driver.Fingerprint(fp), err
}
