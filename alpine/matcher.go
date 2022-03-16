package alpine

import (
	"context"

	version "github.com/knqyf263/go-apk-version"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

func (*Matcher) Name() string {
	return "alpine-matcher"
}

func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}

	switch {
	case record.Distribution.DID == ID:
		return true
	case record.Distribution.Name == Name:
		return true
	default:
		return false
	}
}

func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
		driver.DistributionName,
		driver.DistributionPrettyName,
	}
}

func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	v1, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, nil
	}

	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, nil
	}

	if vuln.FixedInVersion == "" {
		return true, nil
	}

	if vuln.FixedInVersion == "0" {
		return false, nil
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
