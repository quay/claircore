package matcher

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"golang.org/x/sync/errgroup"
)

// Match receives an IndexReport and creates a VulnerabilityReport containing matched vulnerabilities
func Match(ctx context.Context, ir *claircore.IndexReport, matchers []driver.Matcher, store vulnstore.Vulnerability) (*claircore.VulnerabilityReport, error) {
	// the vulnerability report we are creating
	vr := &claircore.VulnerabilityReport{
		Hash:            ir.Hash,
		Vulnerabilities: map[int]*claircore.Vulnerability{},
		Details:         map[int][]claircore.Details{},
	}
	// extract IndexRecords from the IndexReport
	records := ir.IndexRecords()
	// a channel where concurrent controllers will deliver vulnerabilities affecting a package.
	// maps a package id to a list of vulnerabilities.
	ctrlC := make(chan map[int][]*claircore.Vulnerability, 1024)
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
	// loop ranges until ctrlC is closed and fully drained
	for vulnsByPackage := range ctrlC {
		// loop unpacks list of vulnerabilities affected a particular package
		for pkgID, vulns := range vulnsByPackage {
			details := &claircore.Details{
				AffectedPackage: *ir.Packages[pkgID],         // lookup package by ID from IndexReport
				IntroducedIn:    ir.PackageIntroduced[pkgID], // lookup layer package was introduced
			}
			// loop links Detail structs to their associated vulnerability ID
			for _, vuln := range vulns {
				// add vulnerability to report
				vr.Vulnerabilities[vuln.ID] = vuln
				// vulnerability details provide the FixedInVersion for our Details struct
				details.FixedInVersion = vuln.FixedInVersion
				// now we associate a list of Details with a discovered vulnerability ID
				if _, ok := vr.Details[vuln.ID]; !ok {
					vr.Details[vuln.ID] = []claircore.Details{*details}
				} else {
					vr.Details[vuln.ID] = append(vr.Details[vuln.ID], *details)
				}
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
