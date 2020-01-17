package alpine

import (
	"fmt"
	"net/http"

	"github.com/quay/claircore/libvuln/driver"
)

const (
	dbURL = "https://raw.githubusercontent.com/alpinelinux/alpine-secdb/master/%s/%s.yaml"
)

// DBUrl will return a fqdn'd url for a given release,repo pair
func DBUrl(release Release, repo Repo) string {
	return fmt.Sprintf(dbURL, release, repo)
}

type Updater struct {
	client  *http.Client
	release Release
	repo    Repo
	url     string
}

var _ driver.Updater = (*Updater)(nil)

// Option configures the provided Updater
type Option func(*Updater) error

// WithURL overrides the default URL to fetch an OVAL database.
func WithURL(url string) Option {
	return func(u *Updater) error {
		u.url = url
		return nil
	}
}

// NewUpdater returns an updater configured according to the provided Options.
func NewUpdater(release Release, repo Repo, opts ...Option) (*Updater, error) {
	u := &Updater{
		client:  http.DefaultClient,
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
