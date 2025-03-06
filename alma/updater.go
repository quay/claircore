package alma

import (
	"context"
	"fmt"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/zlog"
	"net/http"
	"net/url"
	"strconv"
)

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Updater fetches and parses RHEL-flavored OVAL databases.
type Updater struct {
	ovalutil.Fetcher // fetch method promoted via embed
	dist             *claircore.Distribution
	name             string
}

// UpdaterConfig is the configuration expected for any given updater.
//
// See also [ovalutil.FetcherConfig].
type UpdaterConfig struct {
	ovalutil.FetcherConfig
	Release int `json:"release" yaml:"release"`
}

// NewUpdater returns an Updater.
func NewUpdater(release int, uri string) (*Updater, error) {
	u := &Updater{
		name: fmt.Sprintf("alma-%d", release),
		dist: mkRelease(strconv.Itoa(release)),
	}
	var err error
	u.Fetcher.URL, err = url.Parse(uri)
	if err != nil {
		return nil, err
	}
	u.Fetcher.Compression = ovalutil.CompressionBzip2
	return u, nil
}

// Configure implements [driver.Configurable].
func (u *Updater) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/Updater.Configure")
	var cfg UpdaterConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.Release != 0 {
		u.dist = mkRelease(strconv.Itoa(cfg.Release))
	}

	return u.Fetcher.Configure(ctx, cf, c)
}

// Name implements [driver.Updater].
func (u *Updater) Name() string { return u.name }
