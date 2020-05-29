package layerscanner

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// LayerScanner implements the indexer.LayerScanner interface.
type layerScanner struct {
	store indexer.Store

	// weighted semaphore set to incoming concurrency level
	sem *semaphore.Weighted

	// Pre-constructed and configured scanners.
	ps []indexer.PackageScanner
	ds []indexer.DistributionScanner
	rs []indexer.RepositoryScanner
}

// New is the constructor for a LayerScanner.
//
// The provided Context is only used for the duration of the call.
func New(ctx context.Context, concurrent int, opts *indexer.Opts) (indexer.LayerScanner, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/layerscannner/New").
		Logger()
	ps, ds, rs, err := indexer.EcosystemsToScanners(ctx, opts.Ecosystems, opts.Airgap)
	if err != nil {
		fmt.Errorf("failed to extract scanners from ecosystems: %v", err)
	}

	// Configure and filter the scanners
	var i int
	i = 0
	for _, s := range ps {
		if !filter(ctx, &log, opts, s) {
			ps[i] = s
			i++
		}
	}
	ps = ps[:i]
	i = 0
	for _, s := range rs {
		if !filter(ctx, &log, opts, s) {
			rs[i] = s
			i++
		}
	}
	rs = rs[:i]
	i = 0
	for _, s := range ds {
		if !filter(ctx, &log, opts, s) {
			ds[i] = s
			i++
		}
	}
	ds = ds[:i]

	sem := semaphore.NewWeighted(int64(concurrent))
	return &layerScanner{
		store: opts.Store,
		ps:    ps,
		ds:    ds,
		rs:    rs,
		sem:   sem,
	}, nil
}

// Filter configures the provided scanner and reports if it should be filtered
// out of the slice or not.
func filter(ctx context.Context, log *zerolog.Logger, opts *indexer.Opts, s indexer.VersionedScanner) bool {
	n := s.Name()
	var cfgMap map[string]func(interface{}) error
	switch k := s.Kind(); k {
	case "package":
		cfgMap = opts.ScannerConfig.Package
	case "repository":
		cfgMap = opts.ScannerConfig.Repo
	case "distribution":
		cfgMap = opts.ScannerConfig.Dist
	default:
		log.Warn().
			Str("kind", k).
			Str("scanner", n).
			Msg("unknown scanner kind")
		return true
	}

	if f, ok := cfgMap[n]; ok {
		cs, csOK := s.(indexer.ConfigurableScanner)
		rs, rsOK := s.(indexer.RPCScanner)
		switch {
		case !csOK && !rsOK:
			log.Warn().
				Str("scanner", n).
				Msg("configuration present for an unconfigurable scanner, skipping")
		case csOK && rsOK:
			fallthrough
		case !csOK && rsOK:
			if err := rs.Configure(ctx, f, opts.Client); err != nil {
				log.Error().
					Str("scanner", n).
					Err(err).
					Msg("configuration failed")
				return true
			}
		case csOK && !rsOK:
			if err := cs.Configure(ctx, f); err != nil {
				log.Error().
					Str("scanner", n).
					Err(err).
					Msg("configuration failed")
				return true
			}
		}
	}
	return false
}

// Scan performs a concurrency controlled scan of each layer by each configured
// scanner, indexing the results on successful completion.
//
// Scan will launch all layer scan goroutines immediately and then only allow
// the configured limit to proceed.
//
// The provided Context controls cancellation for all scanners. The first error
// reported halts all work and is returned from Scan.
func (ls *layerScanner) Scan(ctx context.Context, manifest claircore.Digest, layers []*claircore.Layer) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/layerscannner/layerScanner.Scan").
		Str("manifest", manifest.String()).
		Logger()
	ctx = log.WithContext(ctx)

	layersToScan := make([]*claircore.Layer, 0, len(layers))
	dedupe := map[string]struct{}{}
	for _, layer := range layers {
		if _, ok := dedupe[layer.Hash.String()]; !ok {
			layersToScan = append(layersToScan, layer)
			dedupe[layer.Hash.String()] = struct{}{}
		}
	}

	g, ctx := errgroup.WithContext(ctx)
	for _, l := range layersToScan {
		ll := l
		for _, s := range ls.ps {
			g.Go(func() error {
				return ls.scanLayer(ctx, ll, s)
			})
		}
		for _, s := range ls.ds {
			g.Go(func() error {
				return ls.scanLayer(ctx, ll, s)
			})
		}
		for _, s := range ls.rs {
			g.Go(func() error {
				return ls.scanLayer(ctx, ll, s)
			})
		}
	}

	return g.Wait()
}

// ScanLayer (along with the result type) handles an individual (scanner, layer)
// pair.
func (ls *layerScanner) scanLayer(ctx context.Context, l *claircore.Layer, s indexer.VersionedScanner) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/layerscannner/layerScanner.scan").
		Str("scanner", s.Name()).
		Str("kind", s.Kind()).
		Str("layer", l.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("scan start")
	defer log.Debug().Msg("scan done")

	// acquire sem
	if err := ls.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer ls.sem.Release(1)

	ok, err := ls.store.LayerScanned(ctx, l.Hash, s)
	if err != nil {
		return err
	}
	if ok {
		log.Debug().Msg("layer already scanned")
		return nil
	}

	var result result
	if err := result.do(ctx, s, l); err != nil {
		return err
	}

	if err = ls.store.SetLayerScanned(ctx, l.Hash, s); err != nil {
		return fmt.Errorf("could not set layer scanned: %v", l)
	}

	return result.store(ctx, ls.store, s, l)
}

// Result is a type that handles the kind-specific bits of the scan process.
type result struct {
	pkgs  []*claircore.Package
	dists []*claircore.Distribution
	repos []*claircore.Repository
}

// Do asserts the Scanner back to having a Scan method, and then calls it.
//
// The success value is captured and the error value is returned by Do.
func (r *result) do(ctx context.Context, s indexer.VersionedScanner, l *claircore.Layer) error {
	var err error
	switch s := s.(type) {
	case indexer.PackageScanner:
		r.pkgs, err = s.Scan(ctx, l)
	case indexer.DistributionScanner:
		r.dists, err = s.Scan(ctx, l)
	case indexer.RepositoryScanner:
		r.repos, err = s.Scan(ctx, l)
	default:
		panic(fmt.Sprintf("programmer error: unknown type %T used as scanner", s))
	}
	return err
}

// Store calls the properly typed store method on whatever value was captured in
// the result.
func (r *result) store(ctx context.Context, store indexer.Store, s indexer.VersionedScanner, l *claircore.Layer) error {
	log := zerolog.Ctx(ctx).With().Logger()
	switch {
	case r.pkgs != nil:
		log.Debug().Int("count", len(r.pkgs)).Msg("scan returned packages")
		return store.IndexPackages(ctx, r.pkgs, l, s)
	case r.dists != nil:
		log.Debug().Int("count", len(r.dists)).Msg("scan returned dists")
		return store.IndexDistributions(ctx, r.dists, l, s)
	case r.repos != nil:
		log.Debug().Int("count", len(r.repos)).Msg("scan returned repos")
		return store.IndexRepositories(ctx, r.repos, l, s)
	}
	log.Debug().Msg("scan returned a nil")
	return nil
}
