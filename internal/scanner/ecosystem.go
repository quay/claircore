package scanner

import "context"

// Ecosystems group together scanners and a Coalescer which are commonly used together.
//
// A typical ecosystem is "DPKG" which will use the DPKG package scanner, the "OS-Release"
// distribution scanner and the "APT" repository scanner.
//
// A Controller will scan layers with all scanners present in its configured ecosystems.
type Ecosystem struct {
	Name                 string
	PackageScanners      func(ctx context.Context) ([]PackageScanner, error)
	DistributionScanners func(ctx context.Context) ([]DistributionScanner, error)
	RepositoryScanners   func(ctx context.Context) ([]RepositoryScanner, error)
	Coalescer            func(ctx context.Context, store Store) (Coalescer, error)
}

// EcosystemsToScanners extracts and dedupes multiple ecosystems and returns their discrete scanners
func EcosystemsToScanners(ctx context.Context, ecosystems []*Ecosystem) ([]PackageScanner, []DistributionScanner, []RepositoryScanner, error) {
	ps := []PackageScanner{}
	ds := []DistributionScanner{}
	rs := []RepositoryScanner{}
	seen := map[string]struct{}{}

	for _, ecosystem := range ecosystems {
		pscanners, err := ecosystem.PackageScanners(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, s := range pscanners {
			if _, ok := seen[s.Name()]; !ok {
				ps = append(ps, s)
				seen[s.Name()] = struct{}{}
			}
		}

		dscanners, err := ecosystem.DistributionScanners(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, s := range dscanners {
			if _, ok := seen[s.Name()]; !ok {
				ds = append(ds, s)
				seen[s.Name()] = struct{}{}
			}
		}

		rscanners, err := ecosystem.RepositoryScanners(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, s := range rscanners {
			if _, ok := seen[s.Name()]; !ok {
				rs = append(rs, s)
				seen[s.Name()] = struct{}{}
			}
		}
	}
	return ps, ds, rs, nil
}
