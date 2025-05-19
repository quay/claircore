package suse

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/Masterminds/semver"
	"github.com/quay/zlog"
	"golang.org/x/net/html"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

//doc:url updater
const base = `https://support.novell.com/security/oval/`

var (
	reELFile = regexp.MustCompile(`suse.linux.enterprise.server.([1-9][1-9]).xml.gz`)
	// This regex is specific enough to exclude 4x.x releases, it will need to be
	// revisited if LEAP gets to 20 and above.
	reLeapFile = regexp.MustCompile(`opensuse.leap.(1[0-9].[0-9]+).xml.gz`)

	minimumLEAP = semver.MustParse("15.5")
)

type Factory struct {
	c    *http.Client
	base *url.URL
}

// UpdaterSet implements [driver.UpdaterSetFactory].
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "suse/Factory.UpdaterSet")
	us := driver.NewUpdaterSet()
	if f.c == nil {
		zlog.Info(ctx).
			Msg("unconfigured")
		return us, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base.String(), nil)
	if err != nil {
		return us, fmt.Errorf("suse: unable to construct request: %w", err)
	}
	zlog.Debug(ctx).
		Stringer("url", f.base).
		Msg("making request")
	res, err := f.c.Do(req)
	if err != nil {
		return us, fmt.Errorf("suse: error requesting %q: %w", f.base.String(), err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return us, fmt.Errorf("suse: unexpected status requesting OVAL dir: %v", res.Status)
	}

	// It's kind of gross having to parse the HTML but the other path,
	// parsing the SHA256SUMs, is more fragile. At least this way we
	// know the file exists with the expected compression.
	dir, err := html.Parse(res.Body)
	if err != nil {
		return us, fmt.Errorf("suse: error parsing HTML: %w", err)
	}

	ups := []*Updater{}
	err = f.createUpdater(&ups, dir)
	if err != nil {
		return us, fmt.Errorf("suse: problems processing OVAL directory: %w", err)
	}
	for _, u := range ups {
		err := us.Add(u)
		if err != nil {
			return us, err
		}
	}
	return us, nil
}

func (f *Factory) createUpdater(ups *[]*Updater, n *html.Node) error {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, a := range n.Attr {
			if a.Key == "href" {
				var d *claircore.Distribution
				if parts := reELFile.FindAllStringSubmatch(a.Val, -1); len(parts) == 1 {
					d = mkELDist(a.Val, parts[0][1])
				}
				if parts := reLeapFile.FindAllStringSubmatch(a.Val, -1); len(parts) == 1 {
					ver := parts[0][1]
					sv, err := semver.NewVersion(ver)
					if err != nil {
						continue
					}
					if sv.Compare(minimumLEAP) > -1 {
						d = mkLeapDist(a.Val, ver)
					}
				}
				if d == nil {
					continue
				}
				uri, err := f.base.Parse(a.Val)
				if err != nil {
					return fmt.Errorf("unable to construct request for %q: %w", a.Val, err)
				}
				u, err := NewUpdater(d, WithURL(uri.String(), "gz"))
				if err != nil {
					return fmt.Errorf("failed to parse uri %q: %w", uri, err)
				}
				*ups = append(*ups, u)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		err := f.createUpdater(ups, c)
		if err != nil {
			return err
		}
	}
	return nil
}

var releases sync.Map

func mkELDist(oURL, ver string) *claircore.Distribution {
	name := strings.TrimSuffix(oURL, ".xml.gz")
	v, _ := releases.LoadOrStore(name, &claircore.Distribution{
		Name:       "SLES",
		DID:        "sles",
		Version:    ver,
		VersionID:  ver,
		PrettyName: "SUSE Linux Enterprise Server " + ver,
	})
	return v.(*claircore.Distribution)
}

func mkLeapDist(oURL, ver string) *claircore.Distribution {
	name := strings.TrimSuffix(oURL, ".xml.gz")
	v, _ := releases.LoadOrStore(name, &claircore.Distribution{
		Name:       "openSUSE Leap",
		DID:        "opensuse-leap",
		Version:    ver,
		VersionID:  ver,
		PrettyName: "openSUSE Leap " + ver,
	})
	return v.(*claircore.Distribution)
}

// FactoryConfig is the configuration accepted by the Factory.
type FactoryConfig struct {
	// URL indicates the base URL for the SecDB layout. It should have a trailing slash.
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	var err error
	u := base
	if cfg.URL != "" {
		u = cfg.URL
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
	}
	f.base, err = url.Parse(u)
	if err != nil {
		return err
	}
	return nil
}

// Updater implements driver.Updater for SUSE.
type Updater struct {
	d                *claircore.Distribution
	u                *url.URL
	ovalutil.Fetcher // promoted Fetch method
}

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Fetcher      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// NewUpdater configures an updater to fetch the specified Release.
func NewUpdater(d *claircore.Distribution, opts ...Option) (*Updater, error) {
	u := &Updater{
		d: d,
	}
	for _, o := range opts {
		if err := o(u); err != nil {
			return nil, err
		}
	}
	if u.Fetcher.URL == nil {
		u.Fetcher.URL = u.u
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
	return fmt.Sprintf(`suse-updater-%s`, strings.ReplaceAll(strings.ToLower(u.d.PrettyName), " ", "."))
}
