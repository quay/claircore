package rhel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel/pulp"
)

var rhelReleases = []Release{
	RHEL6,
	RHEL7,
	RHEL8,
}

// DefaultManifest is the url for the Red Hat OVAL pulp repository.
const DefaultManifest = `https://access.redhat.com/security/data/oval/v2/PULP_MANIFEST`

// NewFactory creates a Factory making updaters based on the contents of the
// provided pulp manifest.
func NewFactory(ctx context.Context, manifest string, opts ...FactoryOption) (*Factory, error) {
	var err error
	f := Factory{
		client: http.DefaultClient, // TODO(hank) Remove DefaultClient
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

// FactoryConfig is the configuration accepted by the rhel updaters.
//
// By convention, this should be in a map called "rhel".
type FactoryConfig struct {
	URL string `json:"url" yaml:"url"`
}

var _ driver.Configurable = (*Factory)(nil)

func (f *Factory) Configure(ctx context.Context, cfg driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/Factory.Configure")
	var fc FactoryConfig

	if err := cfg(&fc); err != nil {
		return err
	}
	zlog.Debug(ctx).Msg("loaded incoming config")

	if fc.URL != "" {
		u, err := url.Parse(fc.URL)
		if err != nil {
			return err
		}
		zlog.Info(ctx).
			Stringer("url", u).
			Msg("configured manifest URL")
		f.url = u
	}

	if c != nil {
		zlog.Info(ctx).
			Msg("configured HTTP client")
		f.client = c
		f.updaterOpts = append(f.updaterOpts, WithClient(c))
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
		if t := f.manifestEtag; t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		// return stub updater to allow us to record that all rhel updaters are up to date
		stubUpdater := Updater{name: "rhel-all"}
		s.Add(&stubUpdater)
		return s, nil
	default:
		return s, fmt.Errorf("unexpected response: %v", res.Status)
	}

	m := pulp.Manifest{}
	if err := m.Load(res.Body); err != nil {
		return s, err
	}

	for _, e := range m {
		name := strings.TrimSuffix(strings.Replace(e.Path, "/", "-", -1), ".oval.xml.bz2")
		uri, err := f.url.Parse(e.Path)
		if err != nil {
			return s, err
		}
		p := uri.Path
		var r Release
		switch {
		case strings.Contains(p, "RHEL9"):
			r = RHEL9
		case strings.Contains(p, "RHEL8"):
			r = RHEL8
		case strings.Contains(p, "RHEL7"):
			// We need to disregard this OVAL stream because some advisories therein have
			// been released with the CPEs identical to those used in classic RHEL stream.
			// This in turn causes false CVEs to appear in scanned images. Red Hat Product
			// Security is working on fixing this situation and the plan is to remove this
			// exception in the future.
			if name == "RHEL7-rhel-7-alt" {
				continue
			}
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
