package omnimatcher

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/ubuntu"
)

// defaultOmniMatcher is the default implementation
// containing all in-tree matchers.
var defaultOmniMatcher = []driver.Matcher{
	&alpine.Matcher{},
	&aws.Matcher{},
	&debian.Matcher{},
	&python.Matcher{},
	&rhel.Matcher{},
	&ubuntu.Matcher{},
}

// OmniMatcher is a aggregation of Matcher implementations.
//
// Its exported methods will call each implementation's method
// of the same name and return the first true value.
//
// Currently Vulnerable is the only method implemented.
type OmniMatcher []driver.Matcher

// NewOmniMatcher is a constructor for an OmniMatcher.
//
// If a nil array of Matchers is provided the default
// containing all in-tree matchers is used.
func New(m []driver.Matcher) OmniMatcher {
	if m == nil {
		return defaultOmniMatcher
	}
	return m
}

// Vulnerable will call each Matcher's Vulnerable method until one returns true.
func (om OmniMatcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	for _, m := range om {
		applicable := m.Filter(record)
		if !applicable {
			continue
		}
		match, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}
