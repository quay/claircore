package rhel // import "github.com/quay/claircore/rhel"

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"

	"github.com/quay/goval-parser/oval"
)

// We currently grab the oval databases db distro-wise.
const dbURL = `https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%d.xml`

var _ driver.Updater = (*Updater)(nil)
var _ driver.FetcherNG = (*Updater)(nil)

// Updater fetches and parses RHEL-flavored OVAL databases.
type Updater struct {
	ovalutil.Fetcher
	name string
}

type Release int

const (
	RHEL3 Release = 3
	RHEL4 Release = 4
	RHEL5 Release = 5
	RHEL6 Release = 6
	RHEL7 Release = 7
	RHEL8 Release = 8
)

// NewUpdater returns an Updater.
func NewUpdater(v Release, opt ...Option) (*Updater, error) {
	u := &Updater{
		name: fmt.Sprintf("rhel-%d-updater", v),
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
		u.Fetcher.Client = http.DefaultClient
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

// Name satisifies the driver.Updater interface.
func (u *Updater) Name() string {
	return u.name
}

// Fetch satisifies the driver.Updater interface.
func (u *Updater) Fetch() (io.ReadCloser, string, error) {
	ctx, done := context.WithTimeout(context.Background(), time.Minute)
	defer done()
	rc, hint, err := u.FetchContext(ctx, "")
	if err != nil {
		return nil, "", err
	}
	return rc, string(hint), nil
}

// Parse satisifies the driver.Updater interface.
func (u *Updater) Parse(r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	return u.ParseContext(context.Background(), r)
}

// ParseContext is like Parse, but with context.
func (u *Updater) ParseContext(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("rhel: unable to decode OVAL document: %w", err)
	}
	return ovalutil.NewRPMInfo(&root).Extract(ctx)
}
