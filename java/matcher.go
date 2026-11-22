package java

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/maven"
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
	rv, err := maven.ParseVersion(record.Package.Version)
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
		iv, err := maven.ParseVersion(introduced)
		if err != nil {
			slog.WarnContext(ctx, "unable to parse maven introduced version",
				"package", vuln.Package.Name,
				"version", introduced)
			return false, err
		}
		// If the package's version is less than the introduced version, it's not vulnerable.
		// EquivalentModuloClassifier guards against versions like "12.10.0" being
		// read as strictly less than "12.10.0.jre11": some Maven artifacts (e.g.
		// per-JDK-target builds) publish an unrecognized version-string suffix
		// identically across every build of a given release, which the indexer
		// can't always recover, so a lossy installed version can't be told apart
		// from the classified one it actually is.
		if rv.Compare(iv) < 0 && !rv.EquivalentModuloClassifier(iv) {
			return false, nil
		}
	}

	fixedVersion := decodedVersions.Get("fixed")
	lastAffected := decodedVersions.Get("lastAffected")
	switch {
	case fixedVersion != "":
		fv, err := maven.ParseVersion(fixedVersion)
		if err != nil {
			slog.WarnContext(ctx, "unable to parse maven fixed version",
				"package", vuln.Package.Name,
				"version", fixedVersion)
			return false, err
		}
		// The package is affected if its version is less than the fixed version.
		// See the EquivalentModuloClassifier note above; the same ambiguity
		// applies symmetrically to the fixed boundary.
		return rv.Compare(fv) < 0 && !rv.EquivalentModuloClassifier(fv), nil
	case lastAffected != "":
		la, err := maven.ParseVersion(lastAffected)
		if err != nil {
			slog.WarnContext(ctx, "unable to parse maven last_affected version",
				"package", vuln.Package.Name,
				"version", lastAffected)
			return false, err
		}
		// The package is affected if its version is less than or equal to the last affected version.
		return rv.Compare(la) <= 0, nil
	}

	// Just say the package is vulnerable, by default.
	return true, nil
}
