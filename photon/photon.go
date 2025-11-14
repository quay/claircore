package photon

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

var upstreamBase *url.URL

func init() {
	//doc:url updater
	const base = `https://packages.vmware.com/photon/photon_oval_definitions/`
	var err error
	upstreamBase, err = url.Parse(base)
	if err != nil {
		panic("static url somehow didn't parse")
	}
}

// Updater implements driver.Updater for Photon.
type Updater struct {
	release          Release
	ovalutil.Fetcher // promoted Fetch method
}

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Fetcher      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// NewUpdater configures an updater to fetch the specified Release.
func NewUpdater(r Release, opts ...Option) (*Updater, error) {
	u := &Updater{
		release: r,
	}
	for _, o := range opts {
		if err := o(u); err != nil {
			return nil, err
		}
	}
	if u.Fetcher.URL == nil {
		// Default to gzip-compressed Photon OVAL filenames:
		// com.vmware.phsa-photon<MAJOR>.xml.gz
		s := string(u.release)
		maj := s
		if i := strings.IndexByte(s, '.'); i >= 0 {
			maj = s[:i]
		}
		filename := "com.vmware.phsa-photon" + maj + ".xml.gz"
		var err error
		u.Fetcher.URL, err = upstreamBase.Parse(filename)
		if err != nil {
			return nil, err
		}
		// Configure default compression to gzip.
		u.Fetcher.Compression = ovalutil.CompressionGzip
	}
	return u, nil
}

// Option configures an Updater.
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

// Name satisfies driver.Updater.
func (u *Updater) Name() string {
	return fmt.Sprintf(`photon-updater-%s`, u.release)
}
