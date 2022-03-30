package indexer

import (
	"context"

	"github.com/quay/zlog"
)

// Ecosystems group together scanners and a Coalescer which are commonly used
// together.
//
// A typical ecosystem is "dpkg" which will use the "dpkg" package indexer, the
// "os-release" distribution scanner and the "apt" repository scanner.
//
// A Controller will scan layers with all scanners present in its configured
// ecosystems.
type Ecosystem struct {
	PackageScanners      func(ctx context.Context) ([]PackageScanner, error)
	DistributionScanners func(ctx context.Context) ([]DistributionScanner, error)
	RepositoryScanners   func(ctx context.Context) ([]RepositoryScanner, error)
	Coalescer            func(ctx context.Context) (Coalescer, error)
	Name                 string
}

// EcosystemsToScanners extracts and dedupes multiple ecosystems and returns
// their discrete scanners.
func EcosystemsToScanners(ctx context.Context, ecosystems []*Ecosystem, disallowRemote bool) ([]PackageScanner, []DistributionScanner, []RepositoryScanner, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "indexer/EcosystemsToScanners")
	ps := []PackageScanner{}
	ds := []DistributionScanner{}
	rs := []RepositoryScanner{}
	seen := struct{ pkg, dist, repo map[string]struct{} }{
		make(map[string]struct{}),
		make(map[string]struct{}),
		make(map[string]struct{}),
	}

	for _, ecosystem := range ecosystems {
		pscanners, err := ecosystem.PackageScanners(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, s := range pscanners {
			n := s.Name()
			if _, ok := seen.pkg[n]; ok {
				continue
			}
			seen.pkg[n] = struct{}{}
			if _, ok := s.(RPCScanner); ok && disallowRemote {
				zlog.Info(ctx).
					Str("scanner", n).
					Msg("disallowed by configuration")
				continue
			}
			ps = append(ps, s)
		}

		dscanners, err := ecosystem.DistributionScanners(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, s := range dscanners {
			n := s.Name()
			if _, ok := seen.dist[n]; ok {
				continue
			}
			seen.dist[n] = struct{}{}
			if _, ok := s.(RPCScanner); ok && disallowRemote {
				zlog.Info(ctx).
					Str("scanner", n).
					Msg("disallowed by configuration")
				continue
			}
			ds = append(ds, s)
		}

		rscanners, err := ecosystem.RepositoryScanners(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, s := range rscanners {
			n := s.Name()
			if _, ok := seen.repo[n]; ok {
				continue
			}
			seen.repo[n] = struct{}{}
			if _, ok := s.(RPCScanner); ok && disallowRemote {
				zlog.Info(ctx).
					Str("scanner", n).
					Msg("disallowed by configuration")
				continue
			}
			rs = append(rs, s)
		}
	}
	return ps, ds, rs, nil
}
