package python

import (
	"context"

	"github.com/quay/zlog"

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
	return []driver.MatchConstraint{}
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// if the vuln is not associated with any package,
	// return not vulnerable.
	if vuln.Package == nil {
		return false, nil
	}

	v, err := pep440.Parse(record.Package.Version)
	if err != nil {
		zlog.Warn(ctx).
			Str("package", record.Package.Name).
			Stringer("version", &v).
			Msg("unable to parse python package version")
		return false, nil
	}
	spec, err := pep440.ParseRange(vuln.Package.Version)
	if err != nil {
		zlog.Warn(ctx).
			Str("advisory", vuln.Name).
			Stringer("range", spec).
			Msg("unable to parse python vulnerability range")
		return false, nil
	}

	return spec.Match(&v), nil
}
