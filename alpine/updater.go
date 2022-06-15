package alpine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

const dbURL = "https://secdb.alpinelinux.org/"

type updater struct {
	client  *http.Client
	release release
	repo    string
	url     string
}

var (
	_ driver.Updater           = (*updater)(nil)
	_ driver.Configurable      = (*updater)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
)

// Factory is an UpdaterSetFactory for ingesting an Alpine SecDB.
//
// Factory expects to be able to discover a directory layout like the one at [https://secdb.alpinelinux.org/] at the configured URL.
// More explictly, it expects:
// - a "last-update" file with opaque contents that change when any constituent database changes
// - contiguously numbered directories with the name "v$maj.$min" starting with "maj" as "3" and "min" as at most "3"
// - JSON files inside those directories named "main.json" or "community.json"
//
// The [Configure] method must be called before the [UpdaterSet] method.
type Factory struct {
	c    *http.Client
	base *url.URL

	mu    sync.Mutex
	stamp []byte
	etag  string
	cur   driver.UpdaterSet
}

// NewFactory returns a constructed Factory.
//
// [Configure] must still be called before [UpdaterSet].
func NewFactory(_ context.Context) (*Factory, error) {
	return &Factory{}, nil
}

// UpdaterSet implements driver.UpdaterSetFactory.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "alpine/Factory.UpdaterSet")
	s := driver.NewUpdaterSet()
	if f.c == nil {
		zlog.Info(ctx).
			Msg("unconfigured")
		return s, nil
	}

	u, err := f.base.Parse("last-update")
	if err != nil {
		return s, fmt.Errorf("alpine: unable to construct request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return s, fmt.Errorf("alpine: unable to construct request: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.etag != "" {
		req.Header.Set(`if-none-match`, f.etag)
	}
	zlog.Debug(ctx).
		Stringer("url", u).
		Msg("making request")
	res, err := f.c.Do(req)
	if err != nil {
		return s, fmt.Errorf("alpine: error requesting %q: %w", u.String(), err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		zlog.Debug(ctx).
			Stringer("url", u).
			Msg("not modified")
		return f.cur, nil
	case http.StatusOK:
	default:
		return s, fmt.Errorf("alpine: unexpected status requesting `last-update`: %v", res.Status)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(res.Body); err != nil {
		return s, fmt.Errorf("alpine: error requesting `last-update`: %w", err)
	}
	if bytes.Equal(f.stamp, b.Bytes()) {
		return f.cur, nil
	}
	newStamp := make([]byte, b.Len())
	copy(newStamp, b.Bytes())
	b.Reset()
	newEtag := res.Header.Get("etag")

	var todo []release
Major:
	for maj := 3; ; maj++ {
		foundLower := false
		min := 0
		if maj == 3 {
			// Start at v3.3. The previous version of the code didn't handle v3.2.
			min = 3
		}
	Minor:
		for ; ; min++ {
			r := release{maj, min}
			u, err := f.base.Parse(r.String() + "/")
			if err != nil {
				return s, fmt.Errorf("alpine: unable to construct request: %w", err)
			}
			ctx := zlog.ContextWithValues(ctx, "url", u.String(), "release", r.String())
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
			if err != nil {
				return s, fmt.Errorf("alpine: unable to construct request: %w", err)
			}
			zlog.Debug(ctx).Msg("checking release")
			res, err := f.c.Do(req)
			if err != nil {
				return s, fmt.Errorf("alpine: error requesting %q: %w", u.String(), err)
			}
			res.Body.Close()
			switch res.StatusCode {
			case http.StatusOK:
				foundLower = true
				todo = append(todo, r)
			case http.StatusNotFound:
				zlog.Debug(ctx).Msg("not found")
				if foundLower {
					break Minor
				}
				break Major
			default:
				zlog.Info(ctx).Str("status", res.Status).Msg("unexpected status reported")
			}
		}
	}
	for _, r := range todo {
		for _, n := range []string{`main`, `community`} {
			u, err := f.base.Parse(path.Join(r.String(), n+".json"))
			if err != nil {
				return s, fmt.Errorf("alpine: unable to construct request: %w", err)
			}
			ctx := zlog.ContextWithValues(ctx, "url", u.String(), "release", r.String(), "repo", n)
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
			if err != nil {
				return s, fmt.Errorf("alpine: unable to construct request: %w", err)
			}
			zlog.Debug(ctx).Msg("checking repository")
			res, err := f.c.Do(req)
			if err != nil {
				return s, fmt.Errorf("alpine: error requesting %q: %w", u.String(), err)
			}
			res.Body.Close()
			switch res.StatusCode {
			case http.StatusOK:
				zlog.Debug(ctx).Msg("found")
			case http.StatusNotFound:
				zlog.Debug(ctx).Msg("not found")
				continue
			default:
				zlog.Info(ctx).Str("status", res.Status).Msg("unexpected status reported")
				continue
			}
			s.Add(&updater{
				repo:    n,
				release: r, // NB: Safe to copy because it's an array.
				url:     u.String(),
			})
		}
	}

	f.etag = newEtag
	f.stamp = newStamp
	f.cur = s
	return s, nil
}

// FactoryConfig is the configuration accepted by the Factory.
//
// By convention, this is keyed by the string "alpine".
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
	u := dbURL
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

func (u *updater) Name() string {
	return fmt.Sprintf("alpine-%s-%s-updater", u.repo, u.release)
}

// UpdaterConfig is the configuration accepted by Alpine updaters.
//
// By convention, this should be in a map called "alpine-${REPO}-${RELEASE}-updater".
// For example, "alpine-main-v3.12-updater".
//
// If a SecDB JSON file is not found at the proper place by [Factory.UpdaterSet], this configuration will not be consulted.
type UpdaterConfig struct {
	// URL overrides any discovered URL for the JSON file.
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
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
