package oracle

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

// Updater implements driver.Updater for Oracle Linux.
type Updater struct {
	year             int
	ovalutil.Fetcher // Fetch method promoted via embed
}

// Option configures the provided Updater.
type Option func(*Updater) error

// NewUpdater returns an updater configured according to the provided Options.
//
// The URL and compression are expected to be set via WithURL by the UpdaterSet.
func NewUpdater(year int, opts ...Option) (*Updater, error) {
	u := Updater{
		year: year,
	}
	for _, o := range opts {
		if err := o(&u); err != nil {
			return nil, err
		}
	}

	return &u, nil
}

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

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Name satisfies the driver.Updater interface.
func (u *Updater) Name() string {
	which := `all`
	if u.year != -1 {
		which = strconv.Itoa(u.year)
	}
	return fmt.Sprintf("oracle-%s-updater", which)
}
