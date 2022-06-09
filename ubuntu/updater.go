package ubuntu

import (
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

const (
	OVALTemplateBzip = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	OVALTemplate     = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml"
)

var shouldBzipFetch = map[Release]bool{
	Artful:  false,
	Bionic:  true,
	Cosmic:  true,
	Disco:   true,
	Precise: false,
	Trusty:  true,
	Xenial:  true,
	Focal:   true,
	Eoan:    true,
	Impish:  true,
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
	// the current vulnerability being parsed. see the Parse() method for more details
	curVuln claircore.Vulnerability
}

func NewUpdater(release Release) *Updater {
	var fetchBzip, ok bool
	if fetchBzip, ok = shouldBzipFetch[release]; !ok {
		return nil
	}

	var url string
	if fetchBzip {
		url = fmt.Sprintf(OVALTemplateBzip, release)
	} else {
		url = fmt.Sprintf(OVALTemplate, release)
	}

	return &Updater{
		url:     url,
		release: release,
		c:       http.DefaultClient, // TODO(hank) Remove DefaultClient
	}
}

func (u *Updater) Name() string {
	return fmt.Sprintf("ubuntu-%s-updater", u.release)
}

func (u *Updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Updater.Configure",
		"updater", u.Name())

	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.URL != "" {
		if _, err := url.Parse(cfg.URL); err != nil {
			return err
		}
		u.url = cfg.URL
		zlog.Info(ctx).
			Msg("configured database URL")
	}
	u.c = c
	zlog.Info(ctx).
		Msg("configured HTTP client")

	return nil
}

// UpdaterConfig is the configuration for the updater.
//
// By convention, this is in a map called "ubuntu-${RELEASE}-updater", e.g.
// "ubuntu-focal-updater".
type UpdaterConfig struct {
	URL string `json:"url" yaml:"url"`
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Updater.Fetch",
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
		if fp := string(fingerprint); fp == "" || fp != resp.Header.Get("etag") {
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
	f, err := tmp.NewFile("", "ubuntu.")
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = resp.Body
	if shouldBzipFetch[u.release] {
		r = bzip2.NewReader(r)
	}
	if _, err := io.Copy(f, r); err != nil {
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
