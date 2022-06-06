package rhcc

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/quay/zlog"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/pkg/tmp"
	"github.com/quay/claircore/rhel"
)

const (
	dbURL  = "https://access.redhat.com/security/data/metrics/cvemap.xml"
	cveURL = "https://access.redhat.com/security/cve/"
)

var (
	_ driver.Updater      = (*updater)(nil)
	_ driver.Configurable = (*updater)(nil)
)

// updater fetches and parses cvemap.xml
type updater struct {
	client *http.Client
	url    string
}

type UpdaterConfig struct {
	URL string `json:"url" yaml:"url"`
}

const updaterName = "rhel-container-updater"

func (*updater) Name() string {
	return updaterName
}

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	if err := us.Add(&updater{}); err != nil {
		return us, err
	}
	return us, nil
}

func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	u.url = dbURL
	u.client = c
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.url = cfg.URL
	}
	return nil
}

func (u *updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/Updater.Fetch")

	zlog.Info(ctx).Str("database", u.url).Msg("starting fetch")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, hint, fmt.Errorf("rhcc: unable to construct request: %w", err)
	}

	if hint != "" {
		zlog.Debug(ctx).
			Str("hint", string(hint)).
			Msg("using hint")
		req.Header.Set("if-none-match", string(hint))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, hint, fmt.Errorf("rhcc: error making request: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		if t := string(hint); t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		zlog.Info(ctx).Msg("database unchanged since last fetch")
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("rhcc: http response error: %s %d", res.Status, res.StatusCode)
	}
	zlog.Debug(ctx).Msg("successfully requested database")

	tf, err := tmp.NewFile("", updaterName+".")
	if err != nil {
		return nil, hint, fmt.Errorf("rhcc: unable to open tempfile: %w", err)
	}
	zlog.Debug(ctx).
		Str("name", tf.Name()).
		Msg("created tempfile")

	var r io.Reader = res.Body
	if _, err := io.Copy(tf, r); err != nil {
		tf.Close()
		return nil, hint, fmt.Errorf("rhcc: unable to copy resp body to tempfile: %w", err)
	}
	if n, err := tf.Seek(0, io.SeekStart); err != nil || n != 0 {
		tf.Close()
		return nil, hint, fmt.Errorf("rhcc: unable to seek database to start: %w", err)
	}
	zlog.Debug(ctx).Msg("decompressed and buffered database")

	hint = driver.Fingerprint(res.Header.Get("etag"))
	zlog.Debug(ctx).
		Str("hint", string(hint)).
		Msg("using new hint")

	return tf, hint, nil
}

func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/Updater.Parse")
	zlog.Info(ctx).Msg("parse start")
	defer r.Close()
	defer zlog.Info(ctx).Msg("parse done")

	var cvemap cveMap
	if err := xml.NewDecoder(r).Decode(&cvemap); err != nil {
		return nil, fmt.Errorf("rhel: unable to decode cvemap: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")

	zlog.Debug(ctx).
		Int("count", len(cvemap.RedHatVulnerabilities)).Msg("found raw entries")

	vs := []*claircore.Vulnerability{}
	for _, vuln := range cvemap.RedHatVulnerabilities {
		description := getDescription(vuln.Details)
		versionsByContainer := make(map[string]map[rhctag.Version]*consolidatedRelease)
		for _, release := range vuln.AffectedReleases {
			match, packageName, version := parseContainerPackage(release.Package)
			if !match {
				continue
			}
			// parse version
			v, err := rhctag.Parse(version)
			if err != nil {
				zlog.Debug(ctx).
					Str("package", packageName).
					Str("version", version).
					Err(err).
					Msgf("tag parse error")
				continue
			}
			// parse severity
			var severity string
			if release.Impact != "" {
				severity = release.Impact
			} else {
				severity = vuln.ThreatSeverity
			}
			titleCase := cases.Title(language.Und)
			severity = titleCase.String(severity)
			// parse cpe
			cpe, err := cpe.Unbind(release.Cpe)
			if err != nil {
				zlog.Warn(ctx).
					Err(err).
					Str("cpe", release.Cpe).
					Msg("could not unbind cpe")
				continue
			}
			// collect minor keys
			minorKey := v.MinorStart()
			// initialize and update the minorKey to consolidated release map
			if versionsByContainer[packageName] == nil {
				versionsByContainer[packageName] = make(map[rhctag.Version]*consolidatedRelease)
			}
			versionsByContainer[packageName][minorKey] = &consolidatedRelease{
				Cpe:          cpe,
				Issued:       release.ReleaseDate.time,
				Severity:     severity,
				AdvisoryLink: release.Advisory.URL,
				AdvisoryName: release.Advisory.Text,
			}
			// initialize and update the fixed in versions slice
			if versionsByContainer[packageName][minorKey].FixedInVersions == nil {
				vs := make(rhctag.Versions, 0)
				versionsByContainer[packageName][minorKey].FixedInVersions = &vs
			}
			newVersions := versionsByContainer[packageName][minorKey].FixedInVersions.Append(v)
			versionsByContainer[packageName][minorKey].FixedInVersions = &newVersions
		}

		// Build the Vulnerability slice
		for pkg, releasesByMinor := range versionsByContainer {
			p := &claircore.Package{
				Name: pkg,
				Kind: claircore.BINARY,
			}
			// sort minor keys
			minorKeys := make(rhctag.Versions, 0)
			for k := range releasesByMinor {
				minorKeys = append(minorKeys, k)
			}
			sort.Sort(minorKeys)
			// iterate minor key map in order
			for idx, minor := range minorKeys {
				// sort the fixed in versions
				sort.Sort(releasesByMinor[minor].FixedInVersions)
				// The first minor version range should match all previous versions
				start := minor
				if idx == 0 {
					start = rhctag.Version{}
				}
				// For containers such as openshift-logging/elasticsearch6-rhel8 we need to match
				// the first Fixed in Version here.
				// Most of the time this will return the only Fixed In Version for minor version
				firstPatch, _ := releasesByMinor[minor].FixedInVersions.First()
				r := &claircore.Range{
					Lower: start.Version(true),
					Upper: firstPatch.Version(false),
				}
				links := fmt.Sprintf("%s %s%s", releasesByMinor[minor].AdvisoryLink, cveURL, vuln.Name)
				v := &claircore.Vulnerability{
					Updater:            updaterName,
					Name:               releasesByMinor[minor].AdvisoryName,
					Description:        description,
					Issued:             releasesByMinor[minor].Issued,
					Severity:           releasesByMinor[minor].Severity,
					NormalizedSeverity: rhel.NormalizeSeverity(releasesByMinor[minor].Severity),
					Package:            p,
					Repo:               &goldRepo,
					Links:              links,
					FixedInVersion:     firstPatch.Original,
					Range:              r,
				}
				vs = append(vs, v)
			}
		}
	}
	zlog.Debug(ctx).
		Int("count", len(vs)).
		Msg("found vulnerabilities")
	return vs, nil
}
