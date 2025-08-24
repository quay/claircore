package alma

import (
	"context"
	"fmt"
	"github.com/quay/zlog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/quay/claircore/libvuln/driver"
)

//doc:url updater
const dbURL = `https://security.almalinux.org/oval/`

const ovalFmt = `org.almalinux.alsa-%d.xml.bz2`

// NewFactory creates a Factory making updaters based on the contents of the
// provided pulp manifest.
func NewFactory(_ context.Context) (*Factory, error) {
	return &Factory{etags: make(map[int]string)}, nil
}

// Factory contains the configuration for fetching and parsing a Pulp manifest.
type Factory struct {
	base   *url.URL
	client *http.Client
	etags  map[int]string
}

// FactoryConfig is the configuration accepted by the rhel updaters.
//
// By convention, this should be in a map called "rhel".
type FactoryConfig struct {
	BaseURL string `json:"base_url" yaml:"base_url"`
}

var _ driver.Configurable = (*Factory)(nil)

// Configure implements [driver.Configurable].
func (f *Factory) Configure(ctx context.Context, cfg driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "alma/Factory.Configure")
	var fc FactoryConfig

	if err := cfg(&fc); err != nil {
		return err
	}
	zlog.Debug(ctx).Msg("loaded incoming config")

	baseURL, err := url.Parse(dbURL)
	if err != nil {
		panic("programmer error: invalid Base URL")
	}
	f.base = baseURL
	if fc.BaseURL != "" {
		u, err := url.Parse(fc.BaseURL)
		if err != nil {
			return err
		}
		zlog.Info(ctx).
			Stringer("base_url", u).
			Msg("configured base URL")
		f.base = u
	}

	if c != nil {
		zlog.Info(ctx).
			Msg("configured HTTP client")
		f.client = c
	}
	return nil
}

// UpdaterSet implements [driver.UpdaterSetFactory].
//
// The returned Updaters determine the [claircore.Distribution] it's associated
// with based on the path in the Pulp manifest.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "alma/Factory.UpdaterSet")

	s := driver.NewUpdaterSet()

	etags := make(map[int]string)

	var done bool
	for i := 8; !done; i++ {
		ctx = zlog.ContextWithValues(ctx, "version", strconv.Itoa(i))
		u, err := f.base.Parse(fmt.Sprintf(ovalFmt, i))
		if err != nil {
			return s, fmt.Errorf("alma: unable to construct request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return s, fmt.Errorf("alma: unable to construct request: %w", err)
		}
		if etag, exists := f.etags[i]; exists {
			req.Header.Set("If-None-Match", etag)
		}

		zlog.Debug(ctx).Msg("checking repository")
		res, err := f.client.Do(req)
		if err != nil {
			return s, fmt.Errorf("alpine: error requesting %q: %w", u.String(), err)
		}
		_ = res.Body.Close()

		switch res.StatusCode {
		case http.StatusOK:
			zlog.Debug(ctx).Msg("found")
			updater, err := NewUpdater(i, u.String())
			if err != nil {
				return s, err
			}
			if err := s.Add(updater); err != nil {
				return s, err
			}
			etags[i] = res.Header.Get("Etag")
		case http.StatusNotModified:
			zlog.Debug(ctx).Msg("not modified")
		case http.StatusNotFound:
			zlog.Debug(ctx).Msg("not found")
			done = true
		default:
			zlog.Info(ctx).Str("status", res.Status).Msg("unexpected status reported")
		}
	}

	// Only add the etags if this is successful.
	for k, v := range etags {
		f.etags[k] = v
	}
	return s, nil
}
