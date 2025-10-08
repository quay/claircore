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
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/quay/claircore/toolkit/types/cvss"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	_ driver.Updater           = (*updater)(nil)
	_ driver.Configurable      = (*updater)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
)

// DefaultURL is the S3 bucket provided by the OSV project.
//
//doc:url updater
const DefaultURL = `https://osv-vulnerabilities.storage.googleapis.com/`

// AliasBaseURL is the URL to prepend to aliases to convert them into links.
const aliasBaseURL = `https://osv.dev/vulnerability/`

// Factory is the UpdaterSetFactory exposed by this package.
//
// [Configure] must be called before [UpdaterSet]. See the [FactoryConfig] type.
type Factory struct {
	root *url.URL
	c    *http.Client
	// Allow is a bool-and-map-of-bool.
	//
	// If populated, only extant entries are allowed. If not populated,
	// everything is allowed. It uses a bool to make a conditional simpler later.
	allow map[string]bool
	etag  string
}

// FactoryConfig is the configuration that this updater accepts.
//
// By convention, it's at a key called "osv".
type FactoryConfig struct {
	// The URL serving data in the same layout as the OSV project's public S3
	// bucket.
	URL string `json:"url" yaml:"url"`
	// Allowlist is a list of ecosystems to allow. When this is unset, all are
	// allowed.
	//
	// Extant ecosystems are discovered at runtime, see the OSV Schema
	// (https://ossf.github.io/osv-schema/) or the "ecosystems.txt" file in the
	// OSV data for the current list.
	Allowlist []string `json:"allowlist" yaml:"allowlist"`
}

// Configure implements driver.Configurable.
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	var err error

	f.c = c
	f.root, err = url.Parse(DefaultURL)
	if err != nil {
		panic(fmt.Sprintf("programmer error: %v", err))
	}

	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		f.root, err = url.Parse(cfg.URL)
		if err != nil {
			return err
		}
	}
	if l := len(cfg.Allowlist); l != 0 {
		f.allow = make(map[string]bool, l)
		for _, a := range cfg.Allowlist {
			f.allow[strings.ToLower(a)] = true
		}
	}

	slog.DebugContext(ctx, "loaded incoming config")
	return nil
}

func (f *Factory) UpdaterSet(ctx context.Context) (s driver.UpdaterSet, err error) {
	s = driver.NewUpdaterSet()
	if f.root == nil || f.c == nil {
		return s, errors.New("osv: factory not configured") // Purposely return an unhandleable error.
	}
	var stats struct {
		ecosystems []string
		skipped    []string
	}
	defer func() {
		// This is an info print so operators can compare their allow list,
		// if need be.
		slog.InfoContext(ctx, "ecosystems stats",
			"ecosystems", stats.ecosystems,
			"skipped", stats.skipped)
	}()

	uri := *f.root
	uri.Path = "/ecosystems.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return s, fmt.Errorf("osv: martian request: %w", err)
	}
	req.Header.Set(`accept`, `text/plain`)
	if f.etag != "" {
		req.Header.Set(`if-none-match`, f.etag)
	}
	res, err := f.c.Do(req)
	if err != nil {
		return s, err
	}
	seen := make(map[string]struct{})
	// This is straight-line through the switch to make sure the Body is closed
	// there.
	switch res.StatusCode {
	case http.StatusOK:
		scr := bufio.NewScanner(res.Body)
		for scr.Scan() {
			k := scr.Text()
			e := strings.ToLower(k)
			// Currently, there's some versioned ecosystems. This branch removes the versioning.
			if idx := strings.Index(e, ":"); idx != -1 {
				e = e[:idx]
			}
			// Check for duplicates, removing the version will create some.
			if _, ok := seen[e]; ok {
				continue
			}
			seen[e] = struct{}{}
			if _, ok := ignore[e]; ok {
				slog.DebugContext(ctx, "ignoring ecosystem", "ecosystem", e)
				continue
			}
			stats.ecosystems = append(stats.ecosystems, e)
			if f.allow != nil && !f.allow[e] {
				stats.skipped = append(stats.skipped, e)
				continue
			}
			name := "osv/" + e
			uri := (*f.root).JoinPath(k, "all.zip")
			up := &updater{name: name, ecosystem: e, c: f.c, uri: uri}
			if err = s.Add(up); err != nil {
				slog.WarnContext(ctx, "failed to add updater to updaterset",
					"reason", err,
					"ecosystem", e)
				continue
			}
		}
		err = scr.Err()
		f.etag = res.Header.Get("etag")
	case http.StatusNotModified:
		return s, nil
	default:
		var buf bytes.Buffer
		buf.ReadFrom(io.LimitReader(res.Body, 256))
		b, _ := httputil.DumpRequest(req, false)
		err = fmt.Errorf("osv: unexpected response from %q: %v (request: %q) (body: %q)", res.Request.URL, res.Status, b, buf)
	}
	if err := res.Body.Close(); err != nil {
		slog.InfoContext(ctx, "error closing ecosystems.txt response body", "reason", err)
	}
	if err != nil {
		return s, err
	}

	return s, nil
}

// Ignore is a set of incoming ecosystems that we can throw out immediately.
var ignore = map[string]struct{}{
	"almalinux":      {}, // Currently not supported.
	"alpine":         {}, // Have a dedicated alpine updater.
	"android":        {}, // AFAIK, there's no Android container runtime.
	"chainguard":     {}, // Currently not supported.
	"debian":         {}, // Have a dedicated debian updater.
	"github actions": {}, // Shouldn't be in containers?
	"linux":          {}, // Containers have no say in the kernel.
	"opensuse":       {}, // Have a dedicated SUSE updater.
	"oss-fuzz":       {}, // Seems to only record git revisions.
	"red hat":        {}, // Have a dedicated Red Hat VEX updater.
	"rocky linux":    {}, // Currently not supported.
	"suse":           {}, // Have a dedicated SUSE updater.
	"ubuntu":         {}, // Have a dedicated ubuntu updater.
	"wolfi":          {}, // Currently not supported.
}

type updater struct {
	name      string
	ecosystem string
	c         *http.Client
	uri       *url.URL
}

func (u *updater) Name() string { return u.name }

type UpdaterConfig struct {
	// The URL serving data dumps behind an S3 API.
	//
	// Authentication is unconfigurable, the ListObjectsV2 API must be publicly
	// accessible.
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	var err error

	u.c = c
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.uri, err = url.Parse(cfg.URL)
		if err != nil {
			return err
		}
	}
	slog.DebugContext(ctx, "loaded incoming config")
	return nil
}

// Fetcher implements driver.Updater.
func (u *updater) Fetch(ctx context.Context, fp driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	out, err := tmp.NewFile("", "osv.fetch.*")
	if err != nil {
		return nil, fp, err
	}
	defer func() {
		if _, err := out.Seek(0, io.SeekStart); err != nil {
			slog.WarnContext(ctx, "unable to seek file back to start", "reason", err)
		}
	}()
	slog.DebugContext(ctx, "opened temporary file for output", "filename", out.Name())
	w := zip.NewWriter(out)
	defer w.Close()
	var ct int
	// Copy the root URI, then append the ecosystem key and file name.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.uri.String(), nil)
	if err != nil {
		return nil, fp, fmt.Errorf("osv: martian request: %w", err)
	}
	req.Header.Set(`accept`, `application/zip`)
	if fp != "" {
		slog.DebugContext(ctx, "using hint", "hint", string(fp))
		req.Header.Set("if-none-match", string(fp))
	}

	res, err := u.c.Do(req)
	if err != nil {
		return nil, fp, err
	}
	// This switch is straight-line code to ensure that the response body is always closed.
	switch res.StatusCode {
	case http.StatusOK:
		n := u.ecosystem + ".zip"
		var dst io.Writer
		dst, err = w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err == nil {
			_, err = io.Copy(dst, res.Body)
		}
		if err != nil {
			break
		}
		slog.DebugContext(ctx, "wrote zip", "name", n)
		ct++
	case http.StatusNotModified:
	default:
		err = fmt.Errorf("osv: unexpected response from %q: %v", res.Request.URL.String(), res.Status)
	}
	if err := res.Body.Close(); err != nil {
		slog.InfoContext(ctx, "error closing advisory zip response body", "reason", err)
	}
	if err != nil {
		return nil, fp, err
	}
	newEtag := res.Header.Get(`etag`)
	slog.InfoContext(ctx, "found updates", "count", ct)
	if ct == 0 {
		return nil, fp, driver.Unchanged
	}

	return out, driver.Fingerprint(newEtag), nil
}

// Fetcher implements driver.Updater.
func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ra, ok := r.(io.ReaderAt)
	if !ok {
		slog.InfoContext(ctx, "spooling to disk")
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
		log := slog.With("dumpfile", zf.Name)
		log.DebugContext(ctx, "found file")
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

		var skipped stats
		var ct int
		for _, zf := range z.File {
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

			log := log.With("advisory", strings.TrimSuffix(path.Base(zf.Name), ".json"))
			if err := ecs.Insert(ctx, log, &skipped, name, &a); err != nil {
				return nil, err
			}
		}
		log.DebugContext(ctx, "processed advisories", "count", ct)
		log.DebugContext(ctx, "skipped advisories",
			"withdrawn", skipped.Withdrawn,
			"unaffected", skipped.Unaffected,
			"ignored", skipped.Ignored)
	}
	slog.InfoContext(ctx, "found vulnerabilities", "count", ecs.Len())

	return ecs.Finalize(), nil
}

type (
	fileStat interface{ Stat() (fs.FileInfo, error) }
	sizer    interface{ Size() int64 }

	stats struct {
		Withdrawn  []string
		Unaffected []string
		Ignored    []string
	}
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
	ecosystemGo       = `Go`
	ecosystemMaven    = `Maven`
	ecosystemNPM      = `npm`
	ecosystemPyPI     = `PyPI`
	ecosystemRubyGems = `RubyGems`
)

func newECS(u string) ecs {
	return ecs{
		Updater:   u,
		pkgindex:  make(map[string]int),
		repoindex: make(map[string]int),
	}
}

type rangeVer struct {
	fixedInVersion string
	semverRange    *claircore.Range
	ecosystemRange url.Values
}

func (e *ecs) Insert(ctx context.Context, log *slog.Logger, skipped *stats, name string, a *advisory) (err error) {
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
		var q cvss.Qualitative
		switch s.Type {
		case `CVSS_V4`:
			proto.Severity = s.Score
			var v cvss.V4
			v, err = cvss.ParseV4(s.Score)
			q = cvss.QualitativeScore(&v)
		case `CVSS_V3`:
			proto.Severity = s.Score
			var v cvss.V3
			v, err = cvss.ParseV3(s.Score)
			q = cvss.QualitativeScore(&v)
		case `CVSS_V2`:
			proto.Severity = s.Score
			var v cvss.V2
			v, err = cvss.ParseV2(s.Score)
			q = cvss.QualitativeScore(&v)
		default:
			// We didn't get a severity from the CVSS scores
			continue
		}
		if err != nil {
			log.InfoContext(ctx, "odd cvss mangling result", "reason", err)
			continue
		}
		switch q {
		case cvss.None:
			proto.NormalizedSeverity = claircore.Negligible // aka None
		case cvss.Low:
			proto.NormalizedSeverity = claircore.Low
		case cvss.Medium:
			proto.NormalizedSeverity = claircore.Medium
		case cvss.High:
			proto.NormalizedSeverity = claircore.High
		case cvss.Critical:
			proto.NormalizedSeverity = claircore.Critical
		}
	}

	if proto.Severity == "" {
		// Try and extract a severity from the database_specific object
		var databaseJSON map[string]json.RawMessage
		if err := json.Unmarshal([]byte(a.Database), &databaseJSON); err == nil {
			var severityString string
			if err := json.Unmarshal(databaseJSON["severity"], &severityString); err == nil {
				proto.Severity = severityString
				proto.NormalizedSeverity = severityFromDBString(severityString)
			}
		}
	}

	for i, ref := range a.References {
		if i != 0 {
			b.WriteByte(' ')
		}
		b.WriteString(ref.URL)
	}
	for i, alias := range a.Aliases {
		if i != 0 || b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(aliasBaseURL + alias)
	}
	proto.Links = b.String()
	for i := range a.Affected {
		af := &a.Affected[i]
		for _, r := range af.Ranges {
			vers := []*rangeVer{}
			switch r.Type {
			case `SEMVER`:
			case `ECOSYSTEM`:
				b.Reset()
			case `GIT`:
				// ignore, not going to fetch source.
				continue
			default:
				log.DebugContext(ctx, "odd range type", "type", r.Type)
			}
			// This does some heavy assumptions about valid inputs.
			vs := &rangeVer{semverRange: &claircore.Range{}, ecosystemRange: url.Values{}}
			var seenIntroduced bool
			for ie := range r.Events {
				ev := r.Events[ie]
				var err error
				switch r.Type {
				case `SEMVER`:
					var ver *semver.Version
					switch {
					case ev.Introduced != "" && seenIntroduced:
						vs = &rangeVer{semverRange: &claircore.Range{}}
						fallthrough
					case ev.Introduced != "":
						seenIntroduced = true
						switch {
						case ev.Introduced == "0": // -Inf
							vs.semverRange.Lower.Kind = `semver`
						default:
							ver, err = semver.NewVersion(ev.Introduced)
							if err == nil {
								vs.semverRange.Lower = claircore.FromSemver(ver)
							}
						}
						// Is this the last event? If so append the range and
						// implicitly terminate.
						if ie == len(r.Events)-1 {
							vers = append(vers, vs)
						}
						continue
					case ev.Fixed != "": // less than
						ver, err = semver.NewVersion(ev.Fixed)
						if err == nil {
							vs.semverRange.Upper = claircore.FromSemver(ver)
							vs.fixedInVersion = ver.Original()
						}
					case ev.LastAffected != "" && len(af.Versions) != 0: // less than equal to
						// TODO(hank) Should be able to convert this to a "less than."
						log.InfoContext(ctx, "unsure how to interpret event",
							"which", "last_affected",
							"event", ev.LastAffected,
							"versions", af.Versions)
					case ev.LastAffected != "": // less than equal to
						// This is semver, so we should be able to calculate the
						// "next" version:
						ver, err = semver.NewVersion(ev.LastAffected)
						if err == nil {
							nv := ver.IncPatch()
							vs.semverRange.Upper = claircore.FromSemver(&nv)
						}
					case ev.Limit == "*": // +Inf
						vs.semverRange.Upper.Kind = `semver`
						vs.semverRange.Upper.V[0] = 65535
					case ev.Limit != "": // Something arbitrary
						log.InfoContext(ctx, "unsure how to interpret event",
							"which", "limit",
							"event", ev.Limit)
					}
				case `ECOSYSTEM`:
					switch af.Package.Ecosystem {
					case ecosystemMaven, ecosystemPyPI, ecosystemRubyGems:
						vs.semverRange = nil
						switch {
						case ev.Introduced != "" && seenIntroduced:
							vs = &rangeVer{ecosystemRange: url.Values{}}
							fallthrough
						case ev.Introduced != "":
							seenIntroduced = true
							switch {
							case ev.Introduced == "0":
							default:
								vs.ecosystemRange.Add("introduced", ev.Introduced)
							}
							if ie == len(r.Events)-1 {
								vers = append(vers, vs)
							}
							continue
						case ev.Fixed != "":
							vs.ecosystemRange.Add("fixed", ev.Fixed)
						case ev.LastAffected != "":
							vs.ecosystemRange.Add("lastAffected", ev.LastAffected)
						}
					case ecosystemGo, ecosystemNPM:
						return fmt.Errorf(`unexpected "ECOSYSTEM" entry for %q ecosystem: %s`, af.Package.Ecosystem, a.ID)
					default:
						switch {
						case ev.Introduced == "0": // -Inf
						case ev.Introduced != "":
						case ev.Fixed != "":
							vs.fixedInVersion = ev.Fixed
						case ev.LastAffected != "":
						case ev.Limit == "*": // +Inf
						case ev.Limit != "":
						}
					}
				}
				if err != nil {
					log.WarnContext(ctx, "event version error", "reason", err)
				}
				vers = append(vers, vs)
			}
			// Now we need to cycle through the ranges and create the vulnerabilities.
			for _, ve := range vers {
				v := e.NewVulnerability()
				(*v) = proto
				v.Range = ve.semverRange
				v.FixedInVersion = ve.fixedInVersion
				if len(ve.ecosystemRange) > 0 {
					switch af.Package.Ecosystem {
					case ecosystemMaven, ecosystemPyPI, ecosystemRubyGems:
						v.FixedInVersion = ve.ecosystemRange.Encode()
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
						e.RemoveVulnerability(v)
						skipped.Ignored = append(skipped.Ignored, fmt.Sprintf("%s(%s,%s)", a.ID, r.Lower.String(), r.Upper.String()))
						continue
					}
				}
				var vs string
				switch r.Type {
				case `ECOSYSTEM`:
					vs = b.String()
				}
				pkgName := af.Package.PURL
				switch af.Package.Ecosystem {
				case ecosystemGo, ecosystemMaven, ecosystemNPM, ecosystemPyPI, ecosystemRubyGems:
					pkgName = af.Package.Name
				}
				pkg, novel := e.LookupPackage(pkgName, vs)
				v.Package = pkg
				switch af.Package.Ecosystem {
				case ecosystemGo, ecosystemMaven, ecosystemNPM, ecosystemPyPI, ecosystemRubyGems:
					v.Package.Kind = claircore.BINARY
				}
				if novel {
					pkg.RepositoryHint = af.Package.Ecosystem
				}
				if repo := e.LookupRepository(name); repo != nil {
					v.Repo = repo
				}
			}

		}
	}
	return nil
}

// severityFromDBString takes a severity string defined in the
// database_specific object and parses it into a claircore.Severity.
// Known severities in the OSV data are (in varying cases):
//   - CRITICAL
//   - HIGH
//   - LOW
//   - MEDIUM
//   - MODERATE
//   - UNKNOWN
func severityFromDBString(s string) (sev claircore.Severity) {
	sev = claircore.Unknown
	switch {
	case strings.EqualFold(s, "unknown"):
		sev = claircore.Unknown
	case strings.EqualFold(s, "negligible"):
		sev = claircore.Negligible
	case strings.EqualFold(s, "low"):
		sev = claircore.Low
	case strings.EqualFold(s, "moderate"), strings.EqualFold(s, "medium"):
		sev = claircore.Medium
	case strings.EqualFold(s, "high"):
		sev = claircore.High
	case strings.EqualFold(s, "critical"):
		sev = claircore.Critical
	}
	return sev
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

// RemoveVulnerability does what it says on the tin.
//
// Will cause copying if the vulnerability is not the most recent returned from
// NewVulnerability.
func (e *ecs) RemoveVulnerability(v *claircore.Vulnerability) {
	// NOTE(hank) This could use a bitset to track occupancy, but I don't know
	// if that's worth the hassle.

	// This is a weird construction, but it's testing for pointer equality
	// backwards through the slice. It's allow to go to a negative index to
	// trigger a panic if the element isn't found. That shouldn't happen.
	//
	// If there's some reason that should be allowed to happen, a defer with a
	// recover can be added here.
	i := len(e.Vulnerability) - 1
	for ; i >= -1 && v != &e.Vulnerability[i]; i-- {
	}
	if i != len(e.Vulnerability)-1 {
		// If this isn't the last element, copy all elements after the
		// discovered position to the memory starting at the discovered
		// position.
		copy(e.Vulnerability[i:], e.Vulnerability[i+1:])
	}
	// Reset the now unused element at the end. Not doing this can leak memory.
	e.Vulnerability[len(e.Vulnerability)-1] = claircore.Vulnerability{}
	e.Vulnerability = e.Vulnerability[:len(e.Vulnerability)-1]
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
			e.Repository[i].URI = `https://repo1.maven.apache.org/maven2`
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
