package java

import (
	"context"
	"fmt"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"net/url"
)

type matcher struct{}

var (
	_ driver.Matcher = (*matcher)(nil)
)

// Name implements driver.Matcher.
func (*matcher) Name() string { return "java-maven" }

func (*matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Name == Repository.Name
}

// Query implements driver.Matcher.
func (*matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{driver.RepositoryName}
}

func (*matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.FixedInVersion == "" {
		return true, nil
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
