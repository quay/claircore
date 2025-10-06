package python

import (
	"context"
	"log/slog"
	"net/url"

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
	// TODO(ross): This is a common pattern for OSV vulnerabilities. This should be moved into
	// a common place for all OSV vulnerability matchers.

	if vuln.FixedInVersion == "" {
		return true, nil
	}

	// Parse the package first. If it cannot be parsed, it cannot properly be analyzed for vulnerabilities.
	rv, err := pep440.Parse(record.Package.Version)
	if err != nil {
		slog.WarnContext(ctx, "unable to parse python package version",
			"package", record.Package.Name,
			"version", &rv)
		return false, err
	}

	decodedVersions, err := url.ParseQuery(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	introduced := decodedVersions.Get("introduced")
	// If there is an introduced version, check if the package's version is lower.
	if introduced != "" {
		iv, err := pep440.Parse(introduced)
		if err != nil {
			slog.WarnContext(ctx, "unable to parse python introduced version",
				"package", vuln.Package.Name,
				"version", introduced)
			return false, err
		}
		// If the package's version is less than the introduced version, it's not vulnerable.
		if rv.Compare(&iv) < 0 {
			return false, nil
		}
	}

	fixedVersion := decodedVersions.Get("fixed")
	lastAffected := decodedVersions.Get("lastAffected")
	switch {
	case fixedVersion != "":
		uv, err := pep440.Parse(fixedVersion)
		if err != nil {
			slog.WarnContext(ctx, "unable to parse python fixed version",
				"package", vuln.Package.Name,
				"version", fixedVersion)
			return false, err
		}
		// The package is affected if its version is less than the fixed version.
		return rv.Compare(&uv) < 0, nil
	case lastAffected != "":
		la, err := pep440.Parse(lastAffected)
		if err != nil {
			slog.WarnContext(ctx, "unable to parse python last_affected version",
				"package", vuln.Package.Name,
				"version", lastAffected)
			return false, err
		}
		// The package is affected if its version is less than or equal to the last affected version.
		return rv.Compare(&la) <= 0, nil
	}

	// Just say the package is vulnerable, by default.
	return true, nil
}
