package ruby

import (
	"context"
	"fmt"
	"net/url"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ driver.Matcher = (*Matcher)(nil)

// Matcher attempts to correlate discovered ruby packages with reported
// vulnerabilities.
type Matcher struct{}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "ruby-gem" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Name == repository
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

	decodedVersions, err := url.ParseQuery(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	// Check for missing upper version
	if !decodedVersions.Has("fixed") && !decodedVersions.Has("lastAffected") {
		return false, fmt.Errorf("ruby: missing upper version")
	}

	upperVersion := decodedVersions.Get("fixed")
	if upperVersion == "" {
		upperVersion = decodedVersions.Get("lastAffected")
	}

	rv, err := NewVersion(record.Package.Version)
	if err != nil {
		zlog.Warn(ctx).
			Str("package", record.Package.Name).
			Str("version", record.Package.Version).
			Msg("unable to parse ruby package version")
		return false, err
	}

	uv, err := NewVersion(upperVersion)
	if err != nil {
		zlog.Warn(ctx).
			Str("vulnerability", vuln.Name).
			Str("package", vuln.Package.Name).
			Str("version", upperVersion).
			Msg("unable to parse ruby vulnerability 'fixed version' or 'last affected'")
		return false, err
	}

	switch {
	case decodedVersions.Has("fixed") && rv.Compare(uv) >= 0:
		return false, nil
	case decodedVersions.Has("lastAffected") && rv.Compare(uv) > 0:
		return false, nil
	case decodedVersions.Has("introduced"):
		introduced := decodedVersions.Get("introduced")
		iv, err := NewVersion(introduced)
		if err != nil {
			zlog.Warn(ctx).
				Str("vulnerability", vuln.Name).
				Str("package", vuln.Package.Name).
				Str("version", introduced).
				Msg("unable to parse ruby vulnerability 'introduced version'")
			return false, err
		}

		if rv.Compare(iv) < 0 {
			return false, nil
		}
	}

	return true, nil
}
