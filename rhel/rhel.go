package rhel // import "github.com/quay/claircore/rhel"

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

// We currently grab the oval databases db distro-wise.
const dbURL = `https://access.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%d.xml`

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Updater fetches and parses RHEL-flavored OVAL databases.
type Updater struct {
	ovalutil.Fetcher // fetch method promoted via embed
	name             string
	release          Release
}

// NewUpdater returns an Updater.
func NewUpdater(v Release, opt ...Option) (*Updater, error) {
	u := &Updater{
		name:    fmt.Sprintf("rhel-%d-updater", v),
		release: v,
	}
	var err error
	u.Fetcher.URL, err = url.Parse(fmt.Sprintf(dbURL, v))
	if err != nil {
		return nil, err
	}
	for _, f := range opt {
		if err := f(u); err != nil {
			return nil, err
		}
	}
	if u.Fetcher.Client == nil {
		u.Fetcher.Client = http.DefaultClient // TODO(hank) Remove DefaultClient
	}
	return u, nil
}

// Option is a type to configure an Updater.
type Option func(*Updater) error

// WithURL overrides the default URL to fetch an OVAL database.
func WithURL(uri, compression string) Option {
	c, cerr := ovalutil.ParseCompressor(compression)
	u, uerr := url.Parse(uri)
	return func(up *Updater) error {
		// Return any errors from the outer function.
		switch {
		case cerr != nil:
			return cerr
		case uerr != nil:
			return uerr
		}
		up.Fetcher.Compression = c
		up.Fetcher.URL = u
		return nil
	}
}

// WithClient sets an http.Client for use with an Updater.
//
// If this Option is not supplied, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.Fetcher.Client = c
		return nil
	}
}

func WithName(n string) Option {
	return func(u *Updater) error {
		u.name = n
		return nil
	}
}

// Name satisifies the driver.Updater interface.
func (u *Updater) Name() string {
	return u.name
}
