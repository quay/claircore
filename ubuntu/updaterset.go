package ubuntu

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
)

//doc:url updater
const (
	defaultAPI = `https://api.launchpad.net/1.0/`
	ovalURL    = `https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml`
)
const defaultName = `ubuntu`

// NewFactory constructs a Factory.
//
// The returned Factory must have [Configure] called before [UpdaterSet].
func NewFactory(ctx context.Context) (*Factory, error) {
	return &Factory{}, nil
}

// Factory implements [driver.UpdaterSetFactory].
//
// [Configure] must be called before [UpdaterSet].
type Factory struct {
	c     *http.Client
	api   string
	force [][2]string
}

// FactoryConfig is the configuration for Factories.
type FactoryConfig struct {
	// URL should be the address of a [Launchpad API] server.
	//
	// [Launchpad API]: https://launchpad.net/+apidoc/1.0.html
	URL string `json:"url" yaml:"url"`
	// Name is the distribution name, as used in talking to the Launchpad API.
	Name string `json:"name" yaml:"name"`
	// Force is a list of name, version pairs to put in the resulting UpdaterSet regardless
	// of their existence or "active" status in the API response. The resulting Updaters
	// will have guesses at reasonable settings, but the individual Updater's configuration
	// should be used to ensure correct parameters.
	//
	// For example, the name, version pair for Ubuntu 20.04 would be "focal", "20.04".
	Force []struct {
		Name    string `json:"name" yaml:"name"`
		Version string `json:"version" yaml:"version"`
	}
}

// Configure implements [driver.Configurable].
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	f.c = c

	u, err := url.Parse(defaultAPI)
	if err != nil {
		panic("programmer error: " + err.Error())
	}
	if cfg.URL != "" {
		u, err = url.Parse(cfg.URL)
		if err != nil {
			return fmt.Errorf("ubuntu: unable to parse provided URL: %w", err)
		}
		slog.InfoContext(ctx, "configured URL")
	}
	n := defaultName
	if cfg.Name != "" {
		n = cfg.Name
	}
	u, err = u.Parse(path.Join(n, "series"))
	if err != nil {
		return fmt.Errorf("ubuntu: unable to parse constructed URL: %w", err)
	}
	f.api = u.String()

	for _, p := range cfg.Force {
		f.force = append(f.force, [2]string{p.Name, p.Version})
	}

	return nil
}

// UpdaterSet implements [driver.UpdaterSetFactory]
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	set := driver.NewUpdaterSet()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.api, nil)
	if err != nil {
		return set, fmt.Errorf("ubuntu: unable to construct request: %w", err)
	}
	// There's no way to do conditional requests to this endpoint, as per [the docs].
	// It should change very slowly, but it seems like there's no alternative to asking for
	// a few KB of JSON every so often.
	//
	// [the docs]: https://help.launchpad.net/API/Hacking
	req.Header.Set(`TE`, `gzip`)
	req.Header.Set(`Accept`, `application/json`)
	res, err := f.c.Do(req)
	if err != nil {
		return set, fmt.Errorf("ubuntu: error requesting series collection: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return set, fmt.Errorf("ubuntu: unexpected status requesting %q: %q", f.api, res.Status)
	}
	var series seriesResponse
	if err := json.NewDecoder(res.Body).Decode(&series); err != nil {
		return set, fmt.Errorf("ubuntu: error requesting series collection: %w", err)
	}

	eg, ctx := errgroup.WithContext(ctx)
	ch := make(chan *distroSeries)
	us := make(chan *updater)
	eg.Go(func() error {
		// Send active distribution series down the channel.
		defer close(ch)
		for i := range series.Entries {
			e := &series.Entries[i]
			mkDist(e.Version, e.Name)
			if !e.Active {
				slog.DebugContext(ctx, "release not active", "release", e.Name)
				continue
			}
			select {
			case ch <- e:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	eg.Go(func() error {
		// Double-check the distribution.
		defer close(us)
		for e := range ch {
			url := fmt.Sprintf(ovalURL, e.Name)
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
			if err != nil {
				return fmt.Errorf("ubuntu: unable to construct request: %w", err)
			}
			req.Header.Set(`accept`, `application/x-bzip2,application/xml;q=0.9`)
			res, err := f.c.Do(req)
			if err != nil {
				return fmt.Errorf("ubuntu: error requesting inspecting OVAL feed: %w", err)
			}
			defer res.Body.Close()
			switch res.StatusCode {
			case http.StatusOK:
			case http.StatusNotFound:
				slog.DebugContext(ctx, "OVAL database missing, skipping",
					"name", e.Name,
					"version", e.Version)
				continue
			default:
				return fmt.Errorf("ubuntu: unexpected status requesting %q: %q", url, res.Status)
			}
			next, err := res.Request.URL.Parse(res.Header.Get(`content-location`))
			if err != nil {
				return fmt.Errorf(`ubuntu: unable to parse "Content-Location": %w`, err)
			}
			us <- &updater{
				url:      next.String(),
				useBzip2: strings.EqualFold(`application/x-bzip2`, res.Header.Get(`content-type`)),
				name:     e.Name,
				id:       e.Version,
			}
		}
		return nil
	})
	eg.Go(func() error {
		// Construct the set
		for u := range us {
			if err := set.Add(u); err != nil {
				return err
			}
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return set, err
	}

	if len(f.force) != 0 {
		slog.InfoContext(ctx, "configuring manually specified updaters")
		ns := make([]string, 0, len(f.force))
		for _, p := range f.force {
			u := &updater{
				url:      fmt.Sprintf(ovalURL+".bz2", p[0]),
				useBzip2: true,
				name:     p[0],
				id:       p[1],
			}
			if err := set.Add(u); err != nil {
				// Already exists, skip.
				slog.DebugContext(ctx, "skipping updater", "reason", err)
				continue
			}
			ns = append(ns, u.Name())
		}
		slog.InfoContext(ctx, "added specified updaters", "updaters", ns)
	}

	return set, nil
}

type seriesResponse struct {
	Entries []distroSeries `json:"entries"`
}

type distroSeries struct {
	Active  bool   `json:"active"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

var releases sync.Map

func mkDist(ver, name string) *claircore.Distribution {
	v, _ := releases.LoadOrStore(ver, &claircore.Distribution{
		Name:            "Ubuntu",
		DID:             "ubuntu",
		VersionID:       ver,
		PrettyName:      "Ubuntu " + ver,
		VersionCodeName: name,
		Version:         fmt.Sprintf("%s (%s)", ver, strings.Title(name)),
	})
	return v.(*claircore.Distribution)
}

func lookupDist(id string) *claircore.Distribution {
	v, ok := releases.Load(id)
	if !ok {
		panic(fmt.Sprintf("programmer error: unknown key %q", id))
	}
	return v.(*claircore.Distribution)
}
