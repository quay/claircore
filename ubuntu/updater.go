package ubuntu

import (
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

const (
	OVALTemplateBzip = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	OVALTemplate     = "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml"
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
		c:       http.DefaultClient,
	}
}

func (u *Updater) Name() string {
	return fmt.Sprintf("ubuntu-%s-updater", u.release)
}

func (u *Updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ubuntu/Updater.Fetch").
		Str("database", u.url).
		Logger()
	ctx = log.WithContext(ctx)

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
		log.Info().Msg("fetching latest oval database")
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

	log.Info().Msg("fetched latest oval database successfully")
	return f, driver.Fingerprint(fp), err
}
