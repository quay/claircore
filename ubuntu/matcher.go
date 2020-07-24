package ubuntu

import (
	"context"

	version "github.com/knqyf263/go-deb-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	OSReleaseID   = "ubuntu"
	OSReleaseName = "Ubuntu"
)

var _ driver.Matcher = (*Matcher)(nil)

type Matcher struct{}

func (*Matcher) Name() string {
	return "ubuntu-matcher"
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
	if vuln.FixedInVersion == "" {
		return true, nil
	}

	v1, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, err
	}

	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	if v2.String() == "0" {
		return true, nil
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
