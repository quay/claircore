package debian

import (
	"context"

	version "github.com/knqyf263/go-deb-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

func (*Matcher) Name() string {
	return "debian-matcher"
}

func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case record.Distribution.DID == OSReleaseID:
		return true
	case record.Distribution.Name == OSReleaseName:
		return true
	default:
		return false
	}
}

func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionVersion,
	}
}

func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	v1, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, nil
	}

	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	if vuln.FixedInVersion == "" {
		return true, nil
	}

	if v2.String() == "0" {
		return true, nil
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
