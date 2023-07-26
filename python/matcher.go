package python

import (
	"context"
	"fmt"
	"net/url"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/pep440"
)

var _ driver.Matcher = (*Matcher)(nil)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type Matcher struct{}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "python" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Package.NormalizedVersion.Kind == "pep440"
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	rv, err := pep440.Parse(record.Package.Version)
	if err != nil {
		zlog.Warn(ctx).
			Str("package", record.Package.Name).
			Stringer("version", &rv).
			Msg("unable to parse python package version")
		return false, err
	}

	decodedVersions, err := url.ParseQuery(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}
	upperVersion := decodedVersions.Get("fixed")
	lastAffected := decodedVersions.Get("lastAffected")
	switch {
	case upperVersion != "":
		uv, err := pep440.Parse(upperVersion)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", upperVersion).
				Msg("unable to parse python fixed version")
			return false, err
		}

		if rv.Compare(&uv) >= 0 {
			return false, nil
		}
	case lastAffected != "":
		la, err := pep440.Parse(lastAffected)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", lastAffected).
				Msg("unable to parse python last_affected version")
			return false, err
		}
		// It must be less 0 to be good, if the versions are equal, it's potentially vulnerable.
		if rv.Compare(&la) > 0 {
			return false, nil
		}
	default:
		return false, fmt.Errorf("could not find fixed or last_affected: %s", vuln.FixedInVersion)
	}

	if decodedVersions.Has("introduced") {
		lv, err := pep440.Parse(decodedVersions.Get("introduced"))
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", decodedVersions.Get("introduced")).
				Msg("unable to parse python package version")
			return false, err
		}
		if rv.Compare(&lv) < 0 {
			return false, nil
		}
	}

	return true, nil
}
