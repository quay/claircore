package matcher

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// Controller is a control structure used to find vulnerabilities affecting
// a set of packages.
type Controller struct {
	// an implemented Matcher
	m driver.Matcher
	// a vulnstore.Vulnerability instance for querying vulnerabilities
	store vulnstore.Vulnerability
}

// NewController is a constructor for a Controller
func NewController(m driver.Matcher, store vulnstore.Vulnerability) *Controller {
	return &Controller{
		m:     m,
		store: store,
	}
}

func (mc *Controller) Match(ctx context.Context, records []*claircore.ScanRecord) (map[int][]*claircore.Vulnerability, error) {
	// find the packages the matcher is interested in.
	interested := mc.findInterested(records)

	// early return; do not call db at all
	if len(interested) == 0 {
		return map[int][]*claircore.Vulnerability{}, nil
	}

	// query the vulnstore
	vulns, err := mc.query(ctx, interested)
	if err != nil {
		return nil, err
	}

	// filter the vulns
	filteredVulns := mc.filter(interested, vulns)
	return filteredVulns, nil
}

func (mc *Controller) findInterested(records []*claircore.ScanRecord) []*claircore.ScanRecord {
	out := []*claircore.ScanRecord{}

	for _, record := range records {
		if mc.m.Filter(record) {
			out = append(out, record)
		}
	}

	return out
}

// Query asks the Matcher how we should query the vulnstore then performs the query and returns all
// matched vulnerabilities.
func (mc *Controller) query(ctx context.Context, interested []*claircore.ScanRecord) (map[int][]*claircore.Vulnerability, error) {
	// ask the matcher how we should query the vulnstore
	matchers := mc.m.Query()
	getOpts := vulnstore.GetOpts{
		Matchers: matchers,
	}

	matches, err := mc.store.Get(ctx, interested, getOpts)
	if err != nil {
		return nil, err
	}

	return matches, nil
}

// Filter method asks the matcher if the given package is affected by the returned vulnerability. if so; its added to a result map where the key is the package ID
// and the value is a Vulnerability. if not it is not added to the result.
func (mc *Controller) filter(interested []*claircore.ScanRecord, vulns map[int][]*claircore.Vulnerability) map[int][]*claircore.Vulnerability {
	filtered := map[int][]*claircore.Vulnerability{}

	for _, record := range interested {
		filtered[record.Package.ID] = filterVulns(mc.m, record, vulns[record.Package.ID])
	}

	return filtered
}

// filter returns only the vulnerabilities affected by the provided package.
func filterVulns(m driver.Matcher, record *claircore.ScanRecord, vulns []*claircore.Vulnerability) []*claircore.Vulnerability {
	filtered := []*claircore.Vulnerability{}
	for _, vuln := range vulns {
		if m.Vulnerable(record, vuln) {
			filtered = append(filtered, vuln)
		}
	}
	return filtered
}
