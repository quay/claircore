package chainguard

import (
	"context"
	"fmt"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
	"net/http"
)

//doc:url updater
const (
	chainguardURL = `https://packages.cgr.dev/chainguard/security.json`
	wolfiURL      = `https://packages.wolfi.dev/os/security.json`
)

var (
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.Updater           = (*updater)(nil)
	_ driver.Configurable      = (*updater)(nil)
)

// Factory is an UpdaterSetFactory for ingesting Chainguard and Wolfi SecDBs.
//
// Factory expects to be able to discover a directory layout like the one at [https://secdb.alpinelinux.org/] at the configured URL.
// More explictly, it expects:
// - a "last-update" file with opaque contents that change when any constituent database changes
// - contiguously numbered directories with the name "v$maj.$min" starting with "maj" as "3" and "min" as at most "3"
// - JSON files inside those directories named "main.json" or "community.json"
//
// The [Configure] method must be called before the [UpdaterSet] method.
type Factory struct {
	client *http.Client

	chainguardURL  string
	chainguardETag string

	wolfiURL  string
	wolfiETag string
}

// NewFactory returns a constructed Factory.
//
// [Configure] must still be called before [UpdaterSet].
func NewFactory(_ context.Context) (*Factory, error) {
	return &Factory{
		chainguardURL: chainguardURL,
		wolfiURL:      wolfiURL,
	}, nil
}

// FactoryConfig is the configuration accepted by the Factory.
type FactoryConfig struct {
	// ChainguardURL indicates the URL for the Chainguard SecDB.
	ChainguardURL string `json:"chainguard_url" yaml:"chainguard_url"`
	// WolfiURL indicates the URL for the Wolfi SecDB.
	WolfiURL string `json:"wolfi_url" yaml:"wolfi_url"`
}

// Configure implements driver.Configurable.
func (f *Factory) Configure(_ context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.client = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.ChainguardURL != "" {
		f.chainguardURL = cfg.ChainguardURL
	}
	if cfg.WolfiURL != "" {
		f.wolfiURL = cfg.WolfiURL
	}
	return nil
}

func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "chainguard/Factory.UpdaterSet")

	s := driver.NewUpdaterSet()

	add, err := addToUpdaterSet(ctx, f.client, f.chainguardURL, f.chainguardETag)
	if err != nil {
		return s, err
	}
	if add {
		s.Add(&updater{
			name: "chainguard-updater",
			url:  f.chainguardURL,
		})
	}

	add, err = addToUpdaterSet(ctx, f.client, f.wolfiURL, f.wolfiURL)
	if err != nil {
		return s, err
	}
	if add {
		s.Add(&updater{
			name: "wolfi-updater",
			url:  f.wolfiURL,
		})
	}

	return s, nil
}

func addToUpdaterSet(ctx context.Context, client *http.Client, url, etag string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, fmt.Errorf("chainguard: unable to construct request to %q: %w", url, err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("chainguard: error requesting %q: %w", url, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
		return true, nil
	default:
		return false, fmt.Errorf("chainguard: unexpected status requesting %q: %s", url, res.Status)
	}
}

type updater struct {
	name   string
	client *http.Client
	url    string
}

// UpdaterConfig is the configuration accepted by Chainguard and Wolfi updaters.
//
// By convention, this should be in a map called "chainguard-updater" or "wolfi-updater".
//
// If a SecDB JSON file is not found at the proper place by [Factory.UpdaterSet], this configuration will not be consulted.
type UpdaterConfig struct {
	// URL overrides any discovered URL for the JSON file.
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.url = cfg.URL
		zlog.Info(ctx).
			Str("component", "chainguard/Updater.Configure").
			Str("updater", u.Name()).
			Msg("configured url")
	}
	u.client = c
	return nil
}

func (u *updater) Name() string {
	return u.name
}
