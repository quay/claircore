package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync/atomic"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

// Match receives an IndexReport and creates a VulnerabilityReport containing matched vulnerabilities
func Match(ctx context.Context, ir *claircore.IndexReport, matchers []driver.Matcher, store datastore.Vulnerability) (*claircore.VulnerabilityReport, error) {
	// the vulnerability report we are creating
	vr := &claircore.VulnerabilityReport{
		Hash:                   ir.Hash,
		Packages:               ir.Packages,
		Environments:           ir.Environments,
		Distributions:          ir.Distributions,
		Repositories:           ir.Repositories,
		Vulnerabilities:        map[string]*claircore.Vulnerability{},
		PackageVulnerabilities: map[string][]string{},
	}

	// extract IndexRecords from the IndexReport
	records := ir.IndexRecords()
	// a channel where concurrent controllers will deliver vulnerabilities affecting a package.
	// maps a package id to a list of vulnerabilities.
	ctrlC := make(chan map[string][]*claircore.Vulnerability, 1024)
	// a channel where controller errors will be reported
	errorC := make(chan error, 1024)
	// fan out all controllers, write their output to ctrlC, close ctrlC once all writers finish
	go func() {
		defer close(ctrlC)
		var g errgroup.Group
		for _, m := range matchers {
			mm := m
			g.Go(func() error {
				mc := NewController(mm, store)
				vulns, err := mc.Match(ctx, records)
				if err != nil {
					return err
				}
				// in event of slow reader go routines will block
				ctrlC <- vulns
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			errorC <- err
		}
	}()
	// loop ranges until ctrlC is closed and fully drained, ctrlC is guaranteed to close
	for vulnsByPackage := range ctrlC {
		for pkgID, vulns := range vulnsByPackage {
			for _, vuln := range vulns {
				vr.Vulnerabilities[vuln.ID] = vuln
				vr.PackageVulnerabilities[pkgID] = append(vr.PackageVulnerabilities[pkgID], vuln.ID)
			}
		}
	}
	select {
	case err := <-errorC:
		return nil, err
	default:
	}
	return vr, nil
}

// Store is the interface that can retrieve Enrichments and Vulnerabilities.
type Store interface {
	datastore.Vulnerability
	datastore.Enrichment
}

// EnrichedMatch receives an IndexReport and creates a VulnerabilityReport
// containing matched vulnerabilities and any relevant enrichments.
func EnrichedMatch(ctx context.Context, ir *claircore.IndexReport, ms []driver.Matcher, es []driver.Enricher, s Store) (*claircore.VulnerabilityReport, error) {
	// the vulnerability report we are creating
	vr := &claircore.VulnerabilityReport{
		Hash:                   ir.Hash,
		Packages:               ir.Packages,
		Environments:           ir.Environments,
		Distributions:          ir.Distributions,
		Repositories:           ir.Repositories,
		Vulnerabilities:        map[string]*claircore.Vulnerability{},
		PackageVulnerabilities: map[string][]string{},
		// The Enrichments member isn't constructed here because it's
		// constructed separately and then added.
	}
	// extract IndexRecords from the IndexReport
	records := ir.IndexRecords()
	lim := runtime.GOMAXPROCS(0)

	// Set up a pool to run matchers
	mCh := make(chan driver.Matcher)
	vCh := make(chan map[string][]*claircore.Vulnerability, lim)
	mg, mctx := errgroup.WithContext(ctx) // match group, match context
	for i := 0; i < lim; i++ {
		mg.Go(func() error { // Worker
			var m driver.Matcher
			for m = range mCh {
				select {
				case <-mctx.Done():
					return mctx.Err()
				default:
				}
				vs, err := NewController(m, s).Match(mctx, records)
				if err != nil {
					return fmt.Errorf("matcher error: %w", err)
				}
				vCh <- vs
			}
			return nil
		})
	}
	// Set up a pool to watch the matchers and attach results to the report.
	var vg errgroup.Group
	vg.Go(func() error { // Pipeline watcher
	Send:
		for _, m := range ms {
			select {
			case <-mctx.Done():
				break Send
			case mCh <- m:
			}
		}
		close(mCh)
		defer close(vCh)
		if err := mg.Wait(); err != nil {
			return err
		}
		return nil
	})
	vg.Go(func() error { // Collector
		for pkgVuln := range vCh {
			for pkg, vs := range pkgVuln {
				for _, v := range vs {
					vr.Vulnerabilities[v.ID] = v
					vr.PackageVulnerabilities[pkg] = append(vr.PackageVulnerabilities[pkg], v.ID)
				}
			}
		}
		return nil
	})
	if err := vg.Wait(); err != nil {
		return nil, err
	}

	// Set up a pool to run the enrichers and attach results to the report.
	eCh := make(chan driver.Enricher)
	type entry struct {
		kind string
		msg  []json.RawMessage
	}
	rCh := make(chan *entry, lim)
	eg, ectx := errgroup.WithContext(ctx)
	eg.Go(func() error { // Sender
	Send:
		for _, e := range es {
			select {
			case eCh <- e:
			case <-ectx.Done():
				break Send
			}
		}
		close(eCh)
		return nil
	})
	eg.Go(func() error { // Collector
		em := make(map[string][]json.RawMessage)
		for e := range rCh {
			em[e.kind] = append(em[e.kind], e.msg...)
		}
		vr.Enrichments = em
		return nil
	})
	// Use an atomic to track closing the results channel.
	ct := uint32(lim)
	for i := 0; i < lim; i++ {
		eg.Go(func() error { // Worker
			defer func() {
				if atomic.AddUint32(&ct, ^uint32(0)) == 0 {
					close(rCh)
				}
			}()
			var e driver.Enricher
			for e = range eCh {
				kind, msg, err := e.Enrich(ectx, getter(s, e.Name()), vr)
				if err != nil {
					zlog.Error(ctx).
						Err(err).
						Msg("enrichment error")
					continue
				}
				if len(msg) == 0 {
					zlog.Debug(ctx).
						Str("name", e.Name()).
						Msg("enricher reported nothing, skipping")
					continue
				}
				res := entry{
					msg:  msg,
					kind: kind,
				}
				select {
				case rCh <- &res:
				case <-ectx.Done():
					return ectx.Err()
				}
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return vr, nil
}

// Getter returns a type implementing driver.EnrichmentGetter.
func getter(s datastore.Enrichment, name string) *enrichmentGetter {
	return &enrichmentGetter{s: s, name: name}
}

type enrichmentGetter struct {
	s    datastore.Enrichment
	name string
}

var _ driver.EnrichmentGetter = (*enrichmentGetter)(nil)

func (e *enrichmentGetter) GetEnrichment(ctx context.Context, tags []string) ([]driver.EnrichmentRecord, error) {
	return e.s.GetEnrichment(ctx, e.name, tags)
}
