package matcher

import (
	"context"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

// Controller is a control structure used to find vulnerabilities affecting
// a set of packages.
type Controller struct {
	// an implemented Matcher
	m driver.Matcher
	// a vulnstore.Vulnerability instance for querying vulnerabilities
	store datastore.Vulnerability
}

// NewController is a constructor for a Controller
func NewController(m driver.Matcher, store datastore.Vulnerability) *Controller {
	return &Controller{
		m:     m,
		store: store,
	}
}

func (mc *Controller) Match(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "internal/matcher/Controller.Match",
		"matcher", mc.m.Name())
	// find the packages the matcher is interested in.
	interested := mc.findInterested(records)
	zlog.Debug(ctx).
		Int("interested", len(interested)).
		Int("records", len(records)).
		Msg("interest")

	// early return; do not call db at all
	if len(interested) == 0 {
		return map[string][]*claircore.Vulnerability{}, nil
	}

	remoteMatcher, matchedVulns, err := mc.queryRemoteMatcher(ctx, interested)
	if remoteMatcher {
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("remote matcher error, returning empty results")
			return map[string][]*claircore.Vulnerability{}, nil
		}
		return matchedVulns, nil
	}

	dbSide, authoritative := mc.dbFilter()
	zlog.Debug(ctx).
		Bool("opt-in", dbSide).
		Bool("authoritative", authoritative).
		Msg("version filter compatible?")

	// query the vulnstore
	vulns, err := mc.query(ctx, interested, dbSide)
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Int("vulnerabilities", len(vulns)).
		Msg("query")

	if authoritative {
		return vulns, nil
	}
	// filter the vulns
	filteredVulns, err := mc.filter(ctx, interested, vulns)
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Int("filtered", len(filteredVulns)).
		Msg("filtered")
	return filteredVulns, nil
}

// If RemoteMatcher exists, it will call the matcher service which runs on a remote
// machine and fetches the vulnerabilities associated with the IndexRecords.
func (mc *Controller) queryRemoteMatcher(ctx context.Context, interested []*claircore.IndexRecord) (bool, map[string][]*claircore.Vulnerability, error) {
	f, ok := mc.m.(driver.RemoteMatcher)
	if !ok {
		return false, nil, nil
	}
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	vulns, err := f.QueryRemoteMatcher(tctx, interested)
	return true, vulns, err
}

// DbFilter reports whether the db-side version filtering can be used, and
// whether it's authoritative.
func (mc *Controller) dbFilter() (bool, bool) {
	f, ok := mc.m.(driver.VersionFilter)
	if !ok {
		return false, false
	}
	return true, f.VersionAuthoritative()
}

func (mc *Controller) findInterested(records []*claircore.IndexRecord) []*claircore.IndexRecord {
	out := []*claircore.IndexRecord{}
	for _, record := range records {
		if mc.m.Filter(record) {
			out = append(out, record)
		}
	}
	return out
}

// Query asks the Matcher how we should query the vulnstore then performs the query and returns all
// matched vulnerabilities.
func (mc *Controller) query(ctx context.Context, interested []*claircore.IndexRecord, dbSide bool) (map[string][]*claircore.Vulnerability, error) {
	// ask the matcher how we should query the vulnstore
	matchers := mc.m.Query()
	getOpts := datastore.GetOpts{
		Matchers:         matchers,
		Debug:            true,
		VersionFiltering: dbSide,
	}
	matches, err := mc.store.Get(ctx, interested, getOpts)
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// Filter method asks the matcher if the given package is affected by the returned vulnerability. if so; its added to a result map where the key is the package ID
// and the value is a Vulnerability. if not it is not added to the result.
func (mc *Controller) filter(ctx context.Context, interested []*claircore.IndexRecord, vulns map[string][]*claircore.Vulnerability) (map[string][]*claircore.Vulnerability, error) {
	filtered := map[string][]*claircore.Vulnerability{}
	for _, record := range interested {
		match, err := filterVulns(ctx, mc.m, record, vulns[record.Package.ID])
		if err != nil {
			return nil, err
		}
		filtered[record.Package.ID] = match
	}
	return filtered, nil
}

// filter returns only the vulnerabilities affected by the provided package.
func filterVulns(ctx context.Context, m driver.Matcher, record *claircore.IndexRecord, vulns []*claircore.Vulnerability) ([]*claircore.Vulnerability, error) {
	filtered := []*claircore.Vulnerability{}
	for _, vuln := range vulns {
		match, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			return nil, err
		}
		if match {
			filtered = append(filtered, vuln)
		}
	}
	return filtered, nil
}
