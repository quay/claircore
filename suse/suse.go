package suse

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

// Release indicates the SUSE release OVAL database to pull from.
type Release string

// These are some known Releases.
const (
	EnterpriseServer15  Release = `suse.linux.enterprise.server.15`
	EnterpriseDesktop15 Release = `suse.linux.enterprise.desktop.15`
	Enterprise15        Release = `suse.linux.enterprise.15`
	EnterpriseServer12  Release = `suse.linux.enterprise.server.12`
	EnterpriseDesktop12 Release = `suse.linux.enterprise.desktop.12`
	Enterprise12        Release = `suse.linux.enterprise.12`
	EnterpriseServer11  Release = `suse.linux.enterprise.server.11`
	EnterpriseDesktop11 Release = `suse.linux.enterprise.desktop.11`
	OpenStackCloud9     Release = `suse.openstack.cloud.9`
	OpenStackCloud8     Release = `suse.openstack.cloud.8`
	OpenStackCloud7     Release = `suse.openstack.cloud.7`
	Leap151             Release = `opensuse.leap.15.1`
	Leap150             Release = `opensuse.leap.15.0`
	Leap423             Release = `opensuse.leap.42.3`
)

var upstreamBase *url.URL

func init() {
	const base = `https://support.novell.com/security/oval/`
	var err error
	upstreamBase, err = url.Parse(base)
	if err != nil {
		panic("static url somehow didn't parse")
	}
}

// Updater implements driver.Updater for SUSE.
type Updater struct {
	release          string
	ovalutil.Fetcher // promoted Fetch method
}

var (
	_ driver.Updater = (*Updater)(nil)
	_ driver.Fetcher = (*Updater)(nil)
)

// NewUpdater configures an updater to fetch the specified Release.
func NewUpdater(r Release, opts ...Option) (*Updater, error) {
	u := &Updater{
		release: string(r),
	}
	for _, o := range opts {
		if err := o(u); err != nil {
			return nil, err
		}
	}
	if u.Fetcher.Client == nil {
		u.Fetcher.Client = http.DefaultClient
	}
	if u.Fetcher.URL == nil {
		var err error
		u.Fetcher.URL, err = upstreamBase.Parse(u.release + ".xml")
		if err != nil {
			return nil, err
		}
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

// WithClient sets an http.Client for use with an Updater.
//
// If this Option is not supplied, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.Fetcher.Client = c
		return nil
	}
}

// Name satisfies driver.Updater.
func (u *Updater) Name() string {
	return fmt.Sprintf(`suse-updater-%s`, u.release)
}

// ParseContext is like Parse, but with context.
func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "suse/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("suse: unable to decode OVAL document: %w", err)
	}
	return ovalutil.NewRPMInfo(&root).Extract(ctx)
}
