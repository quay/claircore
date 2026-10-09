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

	// query the vulnstore. When the database filter is not authoritative,
	// Get applies Vulnerable while scanning and drops the rows it rejects.
	vulns, err := mc.query(ctx, interested, dbSide, authoritative)
	if err != nil {
		return nil, err
	}
	log.DebugContext(ctx, "query", "count", len(vulns))
	return vulns, nil
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
//
// When the database filter is not authoritative, Vulnerable runs inside Get
// and the returned map already excludes rows it rejected.
func (mc *Controller) query(ctx context.Context, interested []*claircore.IndexRecord, dbSide bool, authoritative bool) (map[string][]*claircore.Vulnerability, error) {
	// ask the matcher how we should query the vulnstore
	matchers := mc.m.Query()
	getOpts := datastore.GetOpts{
		Matchers:         matchers,
		Debug:            true,
		VersionFiltering: dbSide,
	}
	if !authoritative {
		getOpts.Vulnerable = mc.m.Vulnerable
	}
	matches, err := mc.store.Get(ctx, interested, getOpts)
	if err != nil {
		return nil, err
	}
	return matches, nil
}
