package java

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher matches discovered Java Maven packages against advisories provided via OSV.
type Matcher struct{}

var (
	_ driver.Matcher = (*Matcher)(nil)
)

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
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	if strings.Contains(record.Package.Version, "redhat") {
		// This is a Red Hat patched jar, it's version can
		// no longer be relied on. Deferring any vuln matching
		// to the native RH components (rhel, rhcc).
		return false, nil
	}

	decodedVersions, err := url.ParseQuery(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	// Check for missing upper version
	if !decodedVersions.Has("fixed") && !decodedVersions.Has("lastAffected") {
		return false, fmt.Errorf("maven: missing upper version")
	}

	upperVersion := decodedVersions.Get("fixed")
	if upperVersion == "" {
		upperVersion = decodedVersions.Get("lastAffected")
	}

	// Check if vulnerable
	rv, err := parseMavenVersion(record.Package.Version)
	if err != nil {
		return false, err
	}

	v2, err := parseMavenVersion(upperVersion)
	if err != nil {
		return false, err
	}

	switch {
	case decodedVersions.Has("lastAffected") && rv.Compare(v2) > 0:
		return false, nil
	case decodedVersions.Has("fixed") && rv.Compare(v2) >= 0:
		return false, nil
	case decodedVersions.Has("introduced"):
		v1, err := parseMavenVersion(decodedVersions.Get("introduced"))
		if err != nil {
			return false, err
		}
		if rv.Compare(v1) < 0 {
			return false, nil
		}
	}

	return true, nil
}
