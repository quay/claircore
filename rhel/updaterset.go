package rhel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel/pulp"
)

var rhelReleases = []Release{
	RHEL6,
	RHEL7,
	RHEL8,
}

// DefaultManifest is the url for the Red Hat OVAL pulp repository.
const DefaultManifest = `https://www.redhat.com/security/data/oval/v2/PULP_MANIFEST`

// NewFactory creates a Factory making updaters based on the contents of the
// provided pulp manifest.
func NewFactory(ctx context.Context, manifest string, opts ...FactoryOption) (*Factory, error) {
	var err error
	f := Factory{
		client: http.DefaultClient,
	}
	f.url, err = url.Parse(manifest)
	if err != nil {
		return nil, err
	}

	for _, o := range opts {
		if err := o(&f); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

// Factory contains the configuration for fetching and parsing a pulp manifest.
type Factory struct {
	url         *url.URL
	client      *http.Client
	updaterOpts []Option

	manifestEtag string
}

type FactoryConfig struct {
	URL string `json:"url", yaml:"url"`
}

func (f *Factory) Configure(ctx context.Context, cfg driver.ConfigUnmarshaler, c *http.Client) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/Factory.Configure").
		Logger()
	var fc FactoryConfig

	if err := cfg(&fc); err != nil {
		return err
	}
	log.Debug().Msg("loaded incoming config")

	if fc.URL != "" {
		u, err := url.Parse(fc.URL)
		if err != nil {
			return err
		}
		log.Info().
			Str("url", u.String()).
			Msg("configured manifest URL")
		f.url = u
	}

	if c != nil {
		log.Info().
			Msg("configured HTTP client")
		f.client = c
	}

	return nil
}

// A FactoryOption is used with New to configure a Factory.
type FactoryOption func(*Factory) error

// FactoryWithClient sets the http.Client used for fetching the pulp manifest.
func FactoryWithClient(h *http.Client) FactoryOption {
	return func(f *Factory) error {
		f.client = h
		return nil
	}
}

// FactoryWithUpdaterOptions provides Options down into created Updaters.
func FactoryWithUpdaterOptions(opts ...Option) FactoryOption {
	return func(f *Factory) error {
		f.updaterOpts = opts
		return nil
	}
}

// UpdaterSet implements driver.UpdaterSetFactory.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	s := driver.NewUpdaterSet()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url.String(), nil)
	if err != nil {
		return s, err
	}
	if f.manifestEtag != "" {
		req.Header.Set("if-none-match", f.manifestEtag)
	}

	res, err := f.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return s, err
	}

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return s, nil
	default:
		return s, fmt.Errorf("unexpected response: %v", res.Status)
	}

	m := pulp.Manifest{}
	if err := m.Load(res.Body); err != nil {
		return s, err
	}

	for _, e := range m {
		name := strings.TrimSuffix(path.Base(e.Path), ".oval.xml.bz2")
		uri, err := f.url.Parse(e.Path)
		if err != nil {
			return s, err
		}
		p := uri.Path
		var r Release
		switch {
		case strings.Contains(p, "RHEL8"):
			r = RHEL8
		case strings.Contains(p, "RHEL7"):
			r = RHEL7
		case strings.Contains(p, "RHEL6"):
			r = RHEL6
		default: // skip
			continue
		}
		up, err := NewUpdater(r, append(f.updaterOpts, WithName(name), WithURL(uri.String(), "bz2"))...)
		if err != nil {
			return s, err
		}
		_ = s.Add(up)
	}
	f.manifestEtag = res.Header.Get("etag")

	return s, nil
}
