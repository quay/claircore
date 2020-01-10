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
