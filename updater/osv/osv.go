// Package osv is an updater for OSV-formatted advisories.
package osv

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
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
	// (https://ossf.github.io/osv-schema/) or the "ecosystems.txt" file in the
	// OSV data for the current list.
	Allowlist []string `json:"allowlist" yaml:"allowlist"`
}

// DefaultURL is the S3 bucket provided by the OSV project.
const DefaultURL = `https://osv-vulnerabilities.storage.googleapis.com/`

var _ driver.Updater = (*updater)(nil)

func (u *updater) Name() string { return `osv` }

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
	"alpine":         {}, // Have a dedicated alpine updater.
	"android":        {}, // AFAIK, there's no Android container runtime.
	"debian":         {}, // Have a dedicated debian updater.
	"github actions": {}, // Shouldn't be in containers?
	"linux":          {}, // Containers have no say in the kernel.
	"oss-fuzz":       {}, // Seems to only record git revisions.
}

type fingerprint struct {
	Etag       string
	Ecosystems []ecoFP
}

type ecoFP struct {
	Ecosystem string
	Key       string
	Etag      string
}

// Fetcher implements driver.Updater.
func (u *updater) Fetch(ctx context.Context, fp driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "updater/osv/updater.Fetch")
	var prevFP fingerprint
	// Tags is a map of key → Etag. The bucket list API response contains
	// Etags, so conditional requests are not even needed.
	if err := json.Unmarshal([]byte(fp), &prevFP); err != nil && fp != "" {
		zlog.Info(ctx).
			AnErr("unmarshal", err).
			Msg("disregarding previous fingerprint")
	}
	var ct int
	var newFP fingerprint

	var todo []ecoFP
	var stats struct {
		ecosystems []string
		skipped    []string
	}
	defer func() {
		// This is an info print so operators can compare their allow list,
		// if need be.
		zlog.Info(ctx).
			Strs("ecosystems", stats.ecosystems).
			Strs("skipped", stats.skipped).
			Msg("ecosystems stats")
	}()

	uri := *u.root
	uri.Path = "/ecosystems.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, fp, fmt.Errorf("osv: martian request: %w", err)
	}
	req.Header.Set(`accept`, `text/plain`)
	if etag := prevFP.Etag; etag != "" {
		req.Header.Set(`if-none-match`, etag)
	}
	res, err := u.c.Do(req)
	if err != nil {
		return nil, fp, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		s := bufio.NewScanner(res.Body)
		for s.Scan() {
			k := s.Text()
			e := strings.ToLower(k)
			// Currently, there's some versioned ecosystems. This branch removes the versioning.
			if idx := strings.Index(e, ":"); idx != -1 {
				e = e[:idx]
			}
			if _, ok := ignore[e]; ok {
				zlog.Debug(ctx).
					Str("ecosystem", e).
					Msg("ignoring ecosystem")
				continue
			}
			stats.ecosystems = append(stats.ecosystems, e)
			if u.allow != nil && !u.allow[e] {
				stats.skipped = append(stats.skipped, e)
				continue
			}
			todo = append(todo, ecoFP{Ecosystem: e, Key: k})
		}
		err = s.Err()
		newFP.Etag = res.Header.Get(`etag`)
	case http.StatusNotModified:
		todo = prevFP.Ecosystems
	default:
		var buf bytes.Buffer
		buf.ReadFrom(io.LimitReader(res.Body, 256))
		b, _ := httputil.DumpRequest(req, false)
		err = fmt.Errorf("osv: unexpected response from %q: %v (request: %q) (body: %q)", res.Request.URL.String(), res.Status, string(b), buf.String())
	}
	if err := res.Body.Close(); err != nil {
		zlog.Info(ctx).
			Err(err).
			Msg("error closing response body")
	}
	if err != nil {
		return nil, fp, err
	}

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
	w := zip.NewWriter(out)
	defer w.Close()
	for _, e := range todo {
		// Copy the root URI, then append the ecosystem key and file name.
		uri := (*u.root).JoinPath(e.Key, "all.zip")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
		if err != nil {
			return nil, fp, fmt.Errorf("osv: martian request: %w", err)
		}
		req.Header.Set(`accept`, `application/zip`)
		if etag := e.Etag; etag != "" {
			req.Header.Set(`if-none-match`, etag)
		}
		res, err := u.c.Do(req)
		if err != nil {
			return nil, fp, err
		}
		// This switch is straight-line code to ensure that the response body is always closed.
		switch res.StatusCode {
		case http.StatusOK:
			n := e.Ecosystem + ".zip"
			var dst io.Writer
			dst, err = w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
			if err == nil {
				_, err = io.Copy(dst, res.Body)
			}
			if err != nil {
				break
			}
			zlog.Debug(ctx).
				Str("name", n).
				Msg("wrote zip")
			ct++
		case http.StatusNotModified:
		default:
			err = fmt.Errorf("osv: unexpected response from %q: %v", res.Request.URL.String(), res.Status)
		}
		res.Body.Close()
		if err != nil {
			return nil, fp, err
		}
		newFP.Ecosystems = append(newFP.Ecosystems, ecoFP{
			Ecosystem: e.Ecosystem,
			Key:       e.Key,
			Etag:      res.Header.Get(`etag`),
		})
	}
	zlog.Info(ctx).
		Int("count", ct).
		Msg("found updates")
	if ct == 0 {
		return nil, fp, driver.Unchanged
	}

	sort.Slice(newFP.Ecosystems, func(i, j int) bool {
		return newFP.Ecosystems[i].Ecosystem < newFP.Ecosystems[j].Ecosystem
	})
	b, err := json.Marshal(newFP)
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
		tf, err := tmp.NewFile("", `osv.parse.spool.*`)
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
		zlog.Info(ctx).
			Msg("found file" + zf.Name)
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
		zlog.Info(ctx).
			Msg(">>>>> found file2:" + name)
		var skipped struct {
			Withdrawn  []string
			Unaffected []string
		}

		var ct int
		for _, zf := range z.File {
			ctx := zlog.ContextWithValues(ctx, "advisory", strings.TrimSuffix(path.Base(zf.Name), ".json"))
			zlog.Info(ctx).
				Msg(">>>>> found unzipped inner file:" + zf.Name)
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

			switch {
			case !a.Withdrawn.IsZero() && now.After(a.Withdrawn):
				skipped.Withdrawn = append(skipped.Withdrawn, a.ID)
				continue
			case len(a.Affected) == 0:
				skipped.Unaffected = append(skipped.Unaffected, a.ID)
				continue
			default:
			}

			if err := ecs.Insert(ctx, name, &a); err != nil {
				return nil, err
			}
		}
		zlog.Debug(ctx).
			Int("count", ct).
			Msg("processed advisories")
		zlog.Debug(ctx).
			Strs("withdrawn", skipped.Withdrawn).
			Strs("unaffected", skipped.Unaffected).
			Msg("skipped advisories")
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

const (
	ecosystemGo = `Go`
)

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
					case ev.LastAffected != "": // less than equal to
						// This is semver, so we should be able to calculate the
						// "next" version:
						ver, err = semver.NewVersion(ev.LastAffected)
						if err == nil {
							nv := ver.IncPatch()
							v.Range.Upper = FromSemver(&nv)
						}
					case ev.Limit == "*": // +Inf
						v.Range.Upper.Kind = `semver`
						v.Range.Upper.V[0] = 65535
					case ev.Limit != "": // Something arbitrary
						zlog.Info(ctx).
							Str("which", "limit").
							Str("event", ev.Limit).
							Msg("unsure how to interpret event")
					}
				case `ECOSYSTEM`:
					switch af.Package.Ecosystem {
					case ecosystemGo:
						panic("ecosystem: go")
					default:
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
				}
				if err != nil {
					zlog.Warn(ctx).Err(err).Msg("event version error")
				}
			}
			if r := v.Range; r != nil {
				// We have an implicit +Inf range if there's a single event,
				// this should catch it?
				if r.Upper.Kind == "" {
					r.Upper.Kind = r.Lower.Kind
					r.Upper.V[0] = 65535
				}
				if r.Lower.Compare(&r.Upper) == 1 {
					zlog.Info(ctx).
						Strs("range", []string{
							r.Lower.String(), r.Upper.String(),
						}).
						Msg("weird range")
					continue
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
