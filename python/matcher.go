package python

import (
	"context"
	"fmt"
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

func (*Matcher) Filter(r *claircore.IndexRecord) bool {
	return r.Repository != nil &&
		r.Repository.Name == Repository.Name
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
	upperVersion := decodedVersions.Get("fixed")
	if upperVersion == "" {
		return false, fmt.Errorf("pypi: missing upper version")
	}

	rv, err := pep440.Parse(record.Package.Version)
	if err != nil {
		return false, err
	}

	v2, err := pep440.Parse(upperVersion)
	if err != nil {
		return false, err
	}

	if rv.Compare(&v2) >= 0 {
		return false, nil
	}

	if decodedVersions.Has("introduced") {
		v1, err := pep440.Parse(decodedVersions.Get("introduced"))
		if err != nil {
			return false, err
		}
		if rv.Compare(&v1) < 0 {
			return false, nil
		}
	}

	return true, nil
}
