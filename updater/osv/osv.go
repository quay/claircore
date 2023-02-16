// Package osv is an updater for OSV-formatted advisories.
package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

// Factory is the UpdaterSetFactory exposed by this package.
//
// All configuration is done on the returned updaters. See the [Config] type.
var Factory driver.UpdaterSetFactory = &factory{}

type factory struct{}

func (factory) UpdaterSet(context.Context) (s driver.UpdaterSet, err error) {
	s = driver.NewUpdaterSet()
	s.Add(&updater{})
	return s, nil
}

type updater struct {
	c    *http.Client
	root *url.URL
	// Allow is a bool-and-map-of-bool.
	//
	// If populated, only extant entries are allowed. If not populated,
	// everything is allowed. It uses a bool to make a conditional simpler later.
	allow map[string]bool
}

// Config is the configuration that this updater accepts.
//
// By convention, it's at a key called "osv".
type Config struct {
	// The URL serving data dumps behind an S3 API.
	//
	// Authentication is unconfigurable, the ListObjectsV2 API must be publicly
	// accessible.
	URL string `json:"url" yaml:"url"`
	// Allowlist is a list of ecosystems to allow. When this is unset, all are
	// allowed.
	//
	// Extant ecosystems are discovered at runtime, see the OSV Schema
	// (https://ossf.github.io/osv-schema/) for the current list.
	Allowlist []string `json:"allowlist" yaml:"allowlist"`
}

// DefaultURL is the S3 bucket provided by the OSV project.
//
//doc:url updater
const DefaultURL = `https://osv-vulnerabilities.storage.googleapis.com/`

var _ driver.Updater = (*updater)(nil)

func (u *updater) Name() string {
	return `osv`
}

// Configure implements driver.Configurable.
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "updater/osv/updater.Configure")
	var err error

	u.c = c
	u.root, err = url.Parse(DefaultURL)
	if err != nil {
		panic(fmt.Sprintf("programmer error: %v", err))
	}

	var cfg Config
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.root, err = url.Parse(cfg.URL)
		if err != nil {
			return err
		}
	}
	if l := len(cfg.Allowlist); l != 0 {
		u.allow = make(map[string]bool, l)
		for _, a := range cfg.Allowlist {
			u.allow[a] = true
		}
	}

	zlog.Debug(ctx).Msg("loaded incoming config")
	return nil
}

// Ignore is a set of incoming ecosystems that we can throw out immediately.
var ignore = map[string]struct{}{
	"linux":    {}, // Containers have no say in the kernel.
	"android":  {}, // AFAIK, there's no Android container runtime.
	"oss-fuzz": {}, // Seems to only record git revisions.
	"debian":   {}, // Have a dedicated debian updater.
	"alpine":   {}, // Have a dedicated alpine updater.
}

// Fetcher implements driver.Updater.
func (u *updater) Fetch(ctx context.Context, fp driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "updater/osv/updater.Fetch")
	// Tags is a map of key → Etag. The bucket list API response contains
	// Etags, so conditional requests are not even needed.
	prevtags := make(map[string]string)
	if err := json.Unmarshal([]byte(fp), &prevtags); err != nil && fp != "" {
		zlog.Info(ctx).
			AnErr("unmarshal", err).
			Msg("disregarding previous fingerprint")
		prevtags = make(map[string]string)
	}
	var ct int
	newtags := make(map[string]string, len(prevtags))

	out, err := tmp.NewFile("", "osv.fetch.*")
	if err != nil {
		return nil, fp, err
	}
	defer func() {
		if _, err := out.Seek(0, io.SeekStart); err != nil {
			zlog.Warn(ctx).
				Err(err).
				Msg("unable to seek file back to start")
		}
	}()
	zlog.Debug(ctx).
		Str("filename", out.Name()).
		Msg("opened temporary file for output")

	eg, ctx := errgroup.WithContext(ctx)
	type todo struct {
		Key, Etag string
		Fetch     bool
	}
	todoCh := make(chan todo, runtime.GOMAXPROCS(0))
	// API walk
	eg.Go(func() error {
		defer close(todoCh)
		var stats struct {
			ecosystems []string
			skipped    []string
			reqCt      int
		}
		defer func() {
			// This is an info print so operators can compare their allow list,
			// if need be.
			zlog.Info(ctx).
				Strs("ecosystems", stats.ecosystems).
				Strs("skipped", stats.skipped).
				Msg("ecosystems stats")
			zlog.Debug(ctx).
				Int("count", stats.reqCt).
				Msg("made API requests")
		}()

		api := *u.root
		v := api.Query()
		v.Set(`list-type`, `2`)
		api.RawQuery = v.Encode()
		api.Path = "/"
		for uri := &api; uri != nil; {
			var list listBucketResult
			list.Contents = make([]contents, 0, 1000) // Space for one full page.
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
			if err != nil {
				return fmt.Errorf("osv: martian request: %w", err)
			}
			req.Header.Set(`accept`, `application/xml`)
			stats.reqCt++
			res, err := u.c.Do(req)
			if err != nil {
				return err
			}
			if res.StatusCode != 200 {
				var buf bytes.Buffer
				buf.ReadFrom(io.LimitReader(res.Body, 256))
				b, _ := httputil.DumpRequest(req, false)
				err = fmt.Errorf("osv: unexpected response from %q: %v (request: %q) (body: %q)", res.Request.URL.String(), res.Status, string(b), buf.String())
			} else {
				dec := xml.NewDecoder(res.Body)
				dec.CharsetReader = xmlutil.CharsetReader
				err = dec.Decode(&list)
			}
			res.Body.Close()
			if err != nil {
				return err
			}

			for i := range list.Contents {
				c := &list.Contents[i]
				d, k := path.Split(c.Key)
				if k != `all.zip` {
					continue
				}
			Check:
				d = strings.ToLower(path.Clean(d))
				if _, ok := ignore[d]; ok {
					zlog.Debug(ctx).
						Str("key", c.Key).
						Str("ecosystem", d).
						Msg("skipping ecosystem")
					continue
				}
				// Currently, there's some versioned ecosystems. This branch removes the versioning.
				if idx := strings.Index(d, ":"); idx != -1 {
					d = d[:idx]
					goto Check
				}
				stats.ecosystems = append(stats.ecosystems, d)
				if u.allow != nil && !u.allow[d] {
					stats.skipped = append(stats.skipped, d)
					continue
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case todoCh <- todo{
					Key:   c.Key,
					Etag:  c.Etag,
					Fetch: c.Etag != prevtags[c.Key],
				}:
				}
			}
			if list.IsTruncated {
				v.Set(`continuation-token`, list.NextContinuationToken)
				api.RawQuery = v.Encode()
			} else {
				uri = nil
			}
		}
		return nil
	})
	// Fetch
	eg.Go(func() error {
		w := zip.NewWriter(out)
		defer w.Close()
		api := *u.root
		for t := range todoCh {
			if !t.Fetch {
				newtags[t.Key] = t.Etag
				continue
			}
			uri := api.ResolveReference(&url.URL{Path: t.Key})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
			if err != nil {
				return fmt.Errorf("osv: martian request: %w", err)
			}
			res, err := u.c.Do(req)
			if err != nil {
				return err
			}
			if res.StatusCode != 200 {
				res.Body.Close()
				return fmt.Errorf("osv: unexpected response from %q: %v", res.Request.URL.String(), res.Status)
			}
			n := strings.ToLower(path.Dir(t.Key)) + ".zip"
			f, err := w.CreateHeader(&zip.FileHeader{
				Name:   n,
				Method: zip.Store,
			})
			if err == nil {
				_, err = io.Copy(f, res.Body)
			}
			res.Body.Close()
			if err != nil {
				return err
			}
			zlog.Debug(ctx).
				Str("name", n).
				Msg("wrote zip")
			newtags[t.Key] = res.Header.Get(`etag`)
			ct++
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, fp, err
	}
	zlog.Info(ctx).
		Int("count", ct).
		Msg("found updates")
	if ct == 0 {
		return nil, fp, driver.Unchanged
	}

	b, err := json.Marshal(newtags)
	if err != nil {
		// Log
		return nil, fp, err
	}
	return out, driver.Fingerprint(b), nil
}

// Fetcher implements driver.Updater.
func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "updater/osv/updater.Parse")
	ra, ok := r.(io.ReaderAt)
	if !ok {
		zlog.Info(ctx).
			Msg("spooling to disk")
		tf, err := tmp.NewFile("", `osv.parse.*`)
		if err != nil {
			return nil, err
		}
		defer tf.Close()
		if _, err := io.Copy(tf, r); err != nil {
			return nil, err
		}
		ra = tf
	}

	var sz int64 = -1
	switch v := ra.(type) {
	case sizer:
		sz = v.Size()
	case fileStat:
		fi, err := v.Stat()
		if err != nil {
			return nil, err
		}
		sz = fi.Size()
	case io.Seeker:
		cur, err := v.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		sz, err = v.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, err
		}
		if _, err := v.Seek(cur, io.SeekStart); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("osv: unable to determine size of zip file")
	}

	z, err := zip.NewReader(ra, sz)
	if err != nil {
		return nil, err
	}

	tf, err := tmp.NewFile("", `osv.parse.*`)
	if err != nil {
		return nil, err
	}
	defer tf.Close()
	now := time.Now()
	ecs := newECS(u.Name())
	for _, zf := range z.File {
		ctx := zlog.ContextWithValues(ctx, "dumpfile", zf.Name)
		zlog.Debug(ctx).
			Msg("found file")
		r, err := zf.Open()
		if err != nil {
			return nil, err
		}
		if _, err := tf.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		sz, err := io.Copy(tf, r)
		if err != nil {
			return nil, err
		}
		z, err := zip.NewReader(tf, sz)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(path.Base(zf.Name), ".zip")

		var ct int
		for _, zf := range z.File {
			ctx := zlog.ContextWithValues(ctx, "advisory", strings.TrimSuffix(path.Base(zf.Name), ".json"))
			ct++
			var a advisory
			rc, err := zf.Open()
			if err != nil {
				return nil, err
			}
			err = json.NewDecoder(rc).Decode(&a)
			rc.Close()
			if err != nil {
				return nil, err
			}

			var skip bool
			ev := zlog.Info(ctx)
			switch {
			case !a.Withdrawn.IsZero() && now.After(a.Withdrawn):
				ev = ev.Str("reason", "withdrawn").Time("withdrawn", a.Withdrawn)
				skip = true
			case len(a.Affected) == 0:
				ev = ev.Str("reason", "no affected entries")
				skip = true
			default:
				ev = ev.Discard()
			}
			ev.Msg("skipping advisory")
			if skip {
				continue
			}

			if err := ecs.Insert(ctx, name, &a); err != nil {
				return nil, err
			}
		}
		zlog.Debug(ctx).
			Int("count", ct).
			Msg("processed advisories")
	}
	zlog.Info(ctx).
		Int("count", ecs.Len()).
		Msg("found vulnerabilities")

	return ecs.Finalize(), nil
}

type (
	fileStat interface{ Stat() (fs.FileInfo, error) }
	sizer    interface{ Size() int64 }
)

// Ecs is an entity-component system for vulnerabilities.
//
// This is organized this way to help consolidate allocations.
type ecs struct {
	Updater string

	pkgindex  map[string]int
	repoindex map[string]int

	Vulnerability []claircore.Vulnerability
	Package       []claircore.Package
	Distribution  []claircore.Distribution
	Repository    []claircore.Repository
}

func newECS(u string) ecs {
	return ecs{
		Updater:   u,
		pkgindex:  make(map[string]int),
		repoindex: make(map[string]int),
	}
}

func (e *ecs) Insert(ctx context.Context, name string, a *advisory) (err error) {
	if a.GitOnly() {
		return nil
	}
	var b strings.Builder
	var proto claircore.Vulnerability
	proto.Name = a.ID
	proto.Description = a.Summary
	proto.Issued = a.Published
	proto.Updater = e.Updater
	proto.NormalizedSeverity = claircore.Unknown
	for _, s := range a.Severity {
		var err error
		switch s.Type {
		case `CVSS_V3`:
			proto.Severity = s.Score
			proto.NormalizedSeverity, err = fromCVSS3(ctx, s.Score)
		case `CVSS_V2`:
			proto.Severity = s.Score
			proto.NormalizedSeverity, err = fromCVSS2(s.Score)
		default:
			continue
		}
		if err != nil {
			zlog.Info(ctx).
				Err(err).
				Msg("odd cvss mangling result")
		}
	}
	for i, ref := range a.References {
		if i != 0 {
			b.WriteByte(' ')
		}
		b.WriteString(ref.URL)
	}
	proto.Links = b.String()
	for i := range a.Affected {
		af := &a.Affected[i]
		v := e.NewVulnerability()
		(*v) = proto
		for _, r := range af.Ranges {
			switch r.Type {
			case `SEMVER`:
				v.Range = &claircore.Range{}
			case `ECOSYSTEM`:
				b.Reset()
			case `GIT`:
				// ignore, not going to fetch source.
				continue
			default:
				zlog.Debug(ctx).
					Str("type", r.Type).
					Msg("odd range type")
			}
			// This does some heavy assumptions about valid inputs.
			for _, ev := range r.Events {
				var err error
				switch r.Type {
				case `SEMVER`:
					var ver *semver.Version
					switch {
					case ev.Introduced == "0": // -Inf
					case ev.Introduced != "":
						ver, err = semver.NewVersion(ev.Introduced)
						if err == nil {
							v.Range.Lower = FromSemver(ver)
						}
					case ev.Fixed != "": // less than
						ver, err = semver.NewVersion(ev.Fixed)
						if err == nil {
							v.Range.Upper = FromSemver(ver)
						}
					case ev.LastAffected != "" && len(af.Versions) != 0: // less than equal to
						// TODO(hank) Should be able to convert this to a "less than."
						zlog.Info(ctx).
							Str("which", "last_affected").
							Str("event", ev.LastAffected).
							Strs("versions", af.Versions).
							Msg("unsure how to interpret event")
					case ev.Limit == "*": // +Inf
					case ev.Limit != "": // Something arbitrary
						zlog.Info(ctx).
							Str("which", "limit").
							Str("event", ev.Limit).
							Msg("unsure how to interpret event")
					}
				case `ECOSYSTEM`:
					switch {
					case ev.Introduced == "0": // -Inf
					case ev.Introduced != "":
					case ev.Fixed != "":
						v.FixedInVersion = ev.Fixed
					case ev.LastAffected != "":
					case ev.Limit == "*": // +Inf
					case ev.Limit != "":
					}
				}
				if err != nil {
					zlog.Warn(ctx).Err(err).Msg("event version error")
				}
			}
			var vs string
			switch r.Type {
			case `ECOSYSTEM`:
				vs = b.String()
			}
			pkg, novel := e.LookupPackage(af.Package.PURL, vs)
			v.Package = pkg
			if novel {
				pkg.RepositoryHint = af.Package.Ecosystem
			}
			if repo := e.LookupRepository(name); repo != nil {
				v.Repo = repo
			}

		}
	}
	return nil
}

// All the methods follow the same pattern: just reslice the slice if
// there's space, or use append to do an alloc+copy.

func (e *ecs) NewVulnerability() *claircore.Vulnerability {
	i := len(e.Vulnerability)
	if cap(e.Vulnerability) > i {
		e.Vulnerability = e.Vulnerability[:i+1]
	} else {
		e.Vulnerability = append(e.Vulnerability, claircore.Vulnerability{})
	}
	return &e.Vulnerability[i]
}

func (e *ecs) LookupPackage(name string, ver string) (*claircore.Package, bool) {
	key := fmt.Sprintf("%s\x00%s", name, ver)
	i, ok := e.pkgindex[key]
	if !ok {
		i = len(e.Package)
		if cap(e.Package) > i {
			e.Package = e.Package[:i+1]
		} else {
			e.Package = append(e.Package, claircore.Package{})
		}
		e.Package[i].Name = name
		e.Package[i].Version = ver
		e.pkgindex[key] = i
	}
	return &e.Package[i], ok
}

func (e *ecs) LookupRepository(name string) (r *claircore.Repository) {
	key := name
	i, ok := e.repoindex[key]
	if !ok {
		i = len(e.Repository)
		if cap(e.Repository) > i {
			e.Repository = e.Repository[:i+1]
		} else {
			e.Repository = append(e.Repository, claircore.Repository{})
		}
		e.Repository[i].Name = name
		switch name {
		case "crates.io":
			e.Repository[i].URI = `https://crates.io/`
		case "go":
			e.Repository[i].URI = `https://pkg.go.dev/`
		case "npm":
			e.Repository[i].URI = `https://www.npmjs.com/`
		case "nuget":
			e.Repository[i].URI = `https://www.nuget.org/packages/`
		case "oss-fuzz":
			e.Repository[i].URI = `https://google.github.io/oss-fuzz/`
		case "packagist":
			e.Repository[i].URI = `https://packagist.org/`
		case "pypi":
			e.Repository[i].URI = `https://pypi.org/`
		case "rubygems":
			e.Repository[i].URI = `https://rubygems.org/gems/`
		case "maven":
			e.Repository[i].URI = `https://maven.apache.org/repository/`
		}
		e.repoindex[key] = i
	}
	return &e.Repository[i]
}

func (e *ecs) Len() int {
	return len(e.Vulnerability)
}

func (e *ecs) Finalize() []*claircore.Vulnerability {
	r := make([]*claircore.Vulnerability, len(e.Vulnerability))
	for i := range e.Vulnerability {
		r[i] = &e.Vulnerability[i]
	}
	return r
}

// FromSemver is the SemVer to claircore.Version mapping used by this package.
func FromSemver(v *semver.Version) (out claircore.Version) {
	out.Kind = `semver`
	// Leave a leading epoch, for good measure.
	out.V[1] = int32(v.Major())
	out.V[2] = int32(v.Minor())
	out.V[3] = int32(v.Patch())
	return out
}
