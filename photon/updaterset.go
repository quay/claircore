package photon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/quay/claircore/libvuln/driver"
)

// UpdaterSet dynamically discovers available Photon OVAL databases from the
// upstream index and returns one updater per discovered major release.
//
// Discovery rules:
// - Match files named com.vmware.phsa-photon<MAJOR>.xml.gz
// Factory implements a dynamic UpdaterSetFactory for Photon that discovers
// available OVAL feeds and constructs per-release updaters.
type Factory struct {
	c    *http.Client
	base *url.URL
}

var (
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
)

// FactoryConfig is the configuration accepted by the Factory.
//
// By convention, this is keyed by the string "photon".
type FactoryConfig struct {
	// URL indicates the base URL for the OVAL layout. It should have a trailing slash.
	URL string `json:"url" yaml:"url"`
}

// NewFactory returns an unconfigured Factory.
func NewFactory(_ context.Context) (*Factory, error) {
	return &Factory{}, nil
}

// Configure implements driver.Configurable.
func (f *Factory) Configure(_ context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	u := upstreamBase.String()
	if cfg.URL != "" {
		u = cfg.URL
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
	}
	var err error
	f.base, err = url.Parse(u)
	return err
}

// UpdaterSet dynamically discovers available Photon OVAL databases from the
// configured index and returns one updater per discovered major release.
//
// This will match files named com.vmware.phsa-photon<MAJOR>.xml.gz
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	c := f.c
	if c == nil {
		c = http.DefaultClient
	}
	base := f.base
	if base == nil {
		base = upstreamBase
	}

	res, err := c.Get(base.String())
	if err != nil {
		return us, fmt.Errorf("photon: discovery request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return us, fmt.Errorf("photon: unexpected status from index: %s", res.Status)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return us, fmt.Errorf("photon: reading index body: %w", err)
	}

	re := regexp.MustCompile(`href="com\.vmware\.phsa-photon(\d+)\.xml\.gz"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return us, fmt.Errorf("photon: no OVAL entries discovered at index")
	}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		filename := "com.vmware.phsa-photon" + m[1] + ".xml.gz"
		u, err := base.Parse(filename)
		if err != nil {
			return us, fmt.Errorf("photon: building feed url: %w", err)
		}
		rel := Release(m[1] + ".0")
		up, err := NewUpdater(rel, WithURL(u.String(), "gz"))
		if err != nil {
			return us, fmt.Errorf("photon: creating updater for %s: %w", rel, err)
		}
		if err := us.Add(up); err != nil {
			return us, err
		}
	}
	return us, nil
}
