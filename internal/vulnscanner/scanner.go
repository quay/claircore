package vulnscanner

import (
	"context"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/matcher"
	"github.com/quay/claircore/internal/vulnstore"
	"golang.org/x/sync/errgroup"
)

// VulnScanner utilizes a claircore.ScanReport to create a claircore.VulnerabilityReport
// takes a fan-in approach where multiple Controllers write to a single channel
// and VulnScanner dedupes and maps.
type VulnScanner struct {
	store    vulnstore.Vulnerability
	matchers []matcher.Matcher
	vr       *claircore.VulnerabilityReport
	sr       *claircore.ScanReport
}

func New(store vulnstore.Vulnerability, matchers []matcher.Matcher) *VulnScanner {
	return &VulnScanner{
		store:    store,
		matchers: matchers,
		vr: &claircore.VulnerabilityReport{
			Vulnerabilities: map[int]*claircore.Vulnerability{},
			Details:         map[int][]claircore.Details{},
		},
	}
}

func (s *VulnScanner) Scan(ctx context.Context, sr *claircore.ScanReport) (*claircore.VulnerabilityReport, error) {
	vC := make(chan map[int][]*claircore.Vulnerability, 1024)
	eC := make(chan error)
	dC := make(chan struct{})
	s.sr = sr

	go s.match(ctx, vC, eC)
	go s.reduce(ctx, vC, dC)

	// wait on signals
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-eC:
		return nil, err
	case <-dC:
		return s.vr, nil
	}
}

// match launches concurrent Controllers and returns discovered vulnerabilites
// on the provided channel. channel is closed once all match controllers return
func (s *VulnScanner) match(ctx context.Context, vC chan map[int][]*claircore.Vulnerability, eC chan error) {
	var g errgroup.Group
	for _, m := range s.matchers {
		// copy to avoid misreference in loop
		mm := m
		// func uses closure scope
		g.Go(func() error {
			mc := matcher.NewController(mm, s.store)
			vulns, err := mc.Match(ctx, s.sr.Packages)
			if err != nil {
				return err
			}
			vC <- vulns
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		eC <- err
	}
	// can safely close chan, all writers are done
	close(vC)
}

// reduce ranges over the provided vuln channel and reduces vulnerabilities to a *claircore.VulnerabilityReport
func (s *VulnScanner) reduce(ctx context.Context, vC chan map[int][]*claircore.Vulnerability, dC chan struct{}) {
	// first loop ranges over the vC channel until closed
	for vulnsByPackageID := range vC {
		for pkgID, vulns := range vulnsByPackageID {
			s.m(partial(*s.sr.Packages[pkgID], s.sr.PackageIntroduced[pkgID]), vulns)
		}
	}
	dC <- struct{}{}
}

// m short for map; uses the method returned from partial to dedupe and map vulnerabilities
// with their associated details
func (s *VulnScanner) m(partial func(fixedIn string) claircore.Details, vulns []*claircore.Vulnerability) {
	for _, vuln := range vulns {
		// dedupe seen vulns
		s.vr.Vulnerabilities[vuln.ID] = vuln

		// map claircore.Details to deduped vuln
		detail := partial(vuln.FixedInVersion)
		if _, ok := s.vr.Details[vuln.ID]; !ok {
			s.vr.Details[vuln.ID] = []claircore.Details{detail}
		} else {
			s.vr.Details[vuln.ID] = append(s.vr.Details[vuln.ID], detail)
		}
	}
}

// partial is a curry function
// returns a function which closes over a partially populated Details struct. returned function
// will be used to return a fully populated Details struct
func partial(affectedPkg claircore.Package, introducedIn string) func(fixedIn string) claircore.Details {
	return func(fixedIn string) claircore.Details {
		details := claircore.Details{
			AffectedPackage: affectedPkg,
			IntroducedIn:    introducedIn,
			FixedInVersion:  fixedIn,
		}
		return details
	}
}
