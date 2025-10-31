package matcher

import (
	"context"
	"log/slog"
	"time"

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

// Match is the entrypoint for [Controller].
func (mc *Controller) Match(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := slog.With("matcher", mc.m.Name())
	// find the packages the matcher is interested in.
	interested := mc.findInterested(records)
	log.DebugContext(ctx, "interest",
		"interested", len(interested),
		"records", len(records))

	// early return; do not call db at all
	if len(interested) == 0 {
		return map[string][]*claircore.Vulnerability{}, nil
	}

	remoteMatcher, matchedVulns, err := mc.queryRemoteMatcher(ctx, interested)
	if remoteMatcher {
		if err != nil {
			log.ErrorContext(ctx, "remote matcher error, returning empty results", "reason", err)
			return map[string][]*claircore.Vulnerability{}, nil
		}
		return matchedVulns, nil
	}

	dbSide, authoritative := mc.dbFilter()
	log.DebugContext(ctx, "version filter compatible?",
		"opt-in", dbSide,
		"authoritative", authoritative)

	// query the vulnstore
	vulns, err := mc.query(ctx, interested, dbSide)
	if err != nil {
		return nil, err
	}
	log.DebugContext(ctx, "query", "count", len(vulns))

	if authoritative {
		return vulns, nil
	}
	// filter the vulns
	filteredVulns, err := mc.filter(ctx, interested, vulns)
	if err != nil {
		return nil, err
	}
	log.DebugContext(ctx, "filtered", "count", len(filteredVulns))
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
		if record.Package.NormalizedVersion.Kind == claircore.UnmatchableKind {
			continue
		}
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
		filtered[record.Package.ID] = append(filtered[record.Package.ID], match...)
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
