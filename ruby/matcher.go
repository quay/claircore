package ruby

import (
	"context"
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
	// TODO(ross): This is a common pattern for OSV vulnerabilities. This should be moved into
	// a common place for all OSV vulnerability matchers.

	if vuln.FixedInVersion == "" {
		return true, nil
	}

	// Parse the package first. If it cannot be parsed, it cannot properly be analyzed for vulnerabilities.
	rv, err := NewVersion(record.Package.Version)
	if err != nil {
		zlog.Warn(ctx).
			Str("package", record.Package.Name).
			Str("version", record.Package.Version).
			Msg("unable to parse ruby gem package version")
		return false, err
	}

	decodedVersions, err := url.ParseQuery(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	introduced := decodedVersions.Get("introduced")
	// If there is an introduced version, check if the package's version is lower.
	if introduced != "" {
		iv, err := NewVersion(introduced)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", introduced).
				Msg("unable to parse ruby gem introduced version")
			return false, err
		}
		// If the package's version is less than the introduced version, it's not vulnerable.
		if rv.Compare(iv) < 0 {
			return false, nil
		}
	}

	fixedVersion := decodedVersions.Get("fixed")
	lastAffected := decodedVersions.Get("lastAffected")
	switch {
	case fixedVersion != "":
		fv, err := NewVersion(fixedVersion)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", fixedVersion).
				Msg("unable to parse ruby gem fixed version")
			return false, err
		}
		// The package is affected if its version is less than the fixed version.
		return rv.Compare(fv) < 0, nil
	case lastAffected != "":
		la, err := NewVersion(lastAffected)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", lastAffected).
				Msg("unable to parse ruby gem last_affected version")
			return false, err
		}
		// The package is affected if its version is less than or equal to the last affected version.
		return rv.Compare(la) <= 0, nil
	}

	// Just say the package is vulnerable, by default.
	return true, nil
}
