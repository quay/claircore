package java

import (
	"context"
	"net/url"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher matches discovered Java Maven packages against advisories provided via OSV.
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "java-maven" }

func (*Matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Name == Repository.Name
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// TODO(ross): This is a common pattern for OSV vulnerabilities. This should be moved into
	// a common place for all OSV vulnerability matchers.

	if vuln.FixedInVersion == "" {
		return true, nil
	}

	// Parse the package first. If it cannot be parsed, it cannot properly be analyzed for vulnerabilities.
	rv, err := parseMavenVersion(record.Package.Version)
	if err != nil {
		return false, err
	}

	decodedVersions, err := url.ParseQuery(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	introduced := decodedVersions.Get("introduced")
	// If there is an introduced version, check if the package's version is lower.
	if introduced != "" {
		iv, err := parseMavenVersion(introduced)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", introduced).
				Msg("unable to parse maven introduced version")
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
		fv, err := parseMavenVersion(fixedVersion)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", fixedVersion).
				Msg("unable to parse maven fixed version")
			return false, err
		}
		// The package is affected if its version is less than the fixed version.
		return rv.Compare(fv) < 0, nil
	case lastAffected != "":
		la, err := parseMavenVersion(lastAffected)
		if err != nil {
			zlog.Warn(ctx).
				Str("package", vuln.Package.Name).
				Str("version", lastAffected).
				Msg("unable to parse maven last_affected version")
			return false, err
		}
		// The package is affected if its version is less than or equal to the last affected version.
		return rv.Compare(la) <= 0, nil
	}

	// Just say the package is vulnerable, by default.
	return true, nil
}
