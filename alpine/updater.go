package alpine

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

const (
	dbURL = "https://secdb.alpinelinux.org/%s/%s.json"
)

// DBUrl will return a URL for the given release and repo pair.
func DBUrl(release Release, repo Repo) string {
	return fmt.Sprintf(dbURL, release, repo)
}

type Updater struct {
	client  *http.Client
	release Release
	repo    Repo
	url     string
}

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Option configures the provided Updater
type Option func(*Updater) error

// WithURL overrides the default URL to fetch an OVAL database.
//
// The default is derived from the Release and Repo arguments passed to
// NewUpdater.
func WithURL(url string) Option {
	return func(u *Updater) error {
		u.url = url
		return nil
	}
}

// WithClient allows changing the client used for fetching databases.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.client = c
		return nil
	}
}

// NewUpdater returns an updater configured according to the provided Options.
func NewUpdater(release Release, repo Repo, opts ...Option) (*Updater, error) {
	u := &Updater{
		client:  http.DefaultClient, // TODO(hank) Remove DefaultClient
		release: release,
		repo:    repo,
		url:     DBUrl(release, repo),
	}

	for _, o := range opts {
		if err := o(u); err != nil {
			return nil, err
		}
	}

	return u, nil
}

func (u *Updater) Name() string {
	return fmt.Sprintf("alpine-%s-%s-updater", u.repo, u.release)
}

// UpdaterConfig is the configuration accepted by Alpine updaters.
//
// By convention, this should be in a map called
// "alpine-${REPO}-${RELEASE}-updater". For example,
// "alpine-main-v3.12-updater".
type UpdaterConfig struct {
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (u *Updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.url = cfg.URL
		zlog.Info(ctx).
			Str("component", "alpine/Updater.Configure").
			Str("updater", u.Name()).
			Msg("configured url")
	}
	u.client = c
	return nil
}
