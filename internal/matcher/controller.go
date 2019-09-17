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

func (mc *Controller) Match(ctx context.Context, pkgs map[int]*claircore.Package) (map[int][]*claircore.Vulnerability, error) {
	// find the packages the matcher is interested in.
	interestedPkgs := mc.findInterested(pkgs)

	// query the vulnstore
	vulns, err := mc.query(ctx, interestedPkgs)
	if err != nil {
		return nil, err
	}

	// filter the vulns
	filteredVulns := mc.filter(interestedPkgs, vulns)
	return filteredVulns, nil
}

func (mc *Controller) findInterested(pkgs map[int]*claircore.Package) map[int]*claircore.Package {
	out := map[int]*claircore.Package{}

	for _, pkg := range pkgs {
		if mc.m.Filter(pkg) {
			out[pkg.ID] = pkg
		}
	}

	return out
}

// Query asks the Matcher how we should query the vulnstore then performs the query and returns all
// matched vulnerabilities.
func (mc *Controller) query(ctx context.Context, interestedPkgs map[int]*claircore.Package) (map[int][]*claircore.Vulnerability, error) {
	// ask the matcher how we should query the vulnstore
	matchers := mc.m.Query()
	getOpts := vulnstore.GetOpts{
		Matchers: matchers,
	}

	// query the vulnstore for the packages this matcher is intersted in.
	tmp := []*claircore.Package{}
	for _, v := range interestedPkgs {
		tmp = append(tmp, v)
	}

	matches, err := mc.store.Get(ctx, tmp, getOpts)
	if err != nil {
		return nil, err
	}

	return matches, nil
}

// Filter method asks the matcher if the given package is affected by the returned vulnerability. if so; its added to a result map where the key is the package ID
// and the value is a Vulnerability. if not it is not added to the result.
func (mc *Controller) filter(interestedPkgs map[int]*claircore.Package, vulns map[int][]*claircore.Vulnerability) map[int][]*claircore.Vulnerability {
	filtered := map[int][]*claircore.Vulnerability{}

	for id, pkg := range interestedPkgs {
		filtered[id] = filterVulns(mc.m, pkg, vulns[id])
	}

	return filtered
}

// filter returns only the vulnerabilities affected by the provided package.
func filterVulns(m driver.Matcher, pkg *claircore.Package, vulns []*claircore.Vulnerability) []*claircore.Vulnerability {
	filtered := []*claircore.Vulnerability{}
	for _, vuln := range vulns {
		if m.Vulnerable(pkg, vuln) {
			filtered = append(filtered, vuln)
		}
	}
	return filtered
}
