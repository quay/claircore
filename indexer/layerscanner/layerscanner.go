package layerscanner

import (
	"context"
	"fmt"
	"runtime"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// layerScanner implements the indexer.layerScanner interface.
type layerScanner struct {
	store indexer.Store

	// Maximum allowed in-flight scanners per Scan call
	inflight int64

	// Pre-constructed and configured scanners.
	ps []indexer.PackageScanner
	ds []indexer.DistributionScanner
	rs []indexer.RepositoryScanner
}

// New is the constructor for a LayerScanner.
//
// The provided Context is only used for the duration of the call.
func New(ctx context.Context, concurrent int, opts *indexer.Opts) (indexer.LayerScanner, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/layerscannner/New")

	switch {
	case concurrent < 1:
		zlog.Warn(ctx).
			Int("value", concurrent).
			Msg("rectifying nonsense 'concurrent' argument")
		fallthrough
	case concurrent == 0:
		concurrent = runtime.GOMAXPROCS(0)
	}

	ps, ds, rs, err := indexer.EcosystemsToScanners(ctx, opts.Ecosystems, opts.Airgap)
	if err != nil {
		return nil, fmt.Errorf("failed to extract scanners from ecosystems: %v", err)
	}
	// Configure and filter the scanners
	var i int
	i = 0
	for _, s := range ps {
		if !configAndFilter(ctx, opts, s) {
			ps[i] = s
			i++
		}
	}
	ps = ps[:i]
	i = 0
	for _, s := range rs {
		if !configAndFilter(ctx, opts, s) {
			rs[i] = s
			i++
		}
	}
	rs = rs[:i]
	i = 0
	for _, s := range ds {
		if !configAndFilter(ctx, opts, s) {
			ds[i] = s
			i++
		}
	}
	ds = ds[:i]

	return &layerScanner{
		store:    opts.Store,
		inflight: int64(concurrent),
		ps:       ps,
		ds:       ds,
		rs:       rs,
	}, nil
}

// ConfigAndFilter configures the provided scanner and reports if it should be
// filtered out of the slice or not.
func configAndFilter(ctx context.Context, opts *indexer.Opts, s indexer.VersionedScanner) bool {
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
		zlog.Warn(ctx).
			Str("kind", k).
			Str("scanner", n).
			Msg("unknown scanner kind")
		return true
	}

	f, haveCfg := cfgMap[n]
	if !haveCfg {
		f = func(interface{}) error { return nil }
	}
	cs, csOK := s.(indexer.ConfigurableScanner)
	rs, rsOK := s.(indexer.RPCScanner)
	switch {
	case haveCfg && !csOK && !rsOK:
		zlog.Warn(ctx).
			Str("scanner", n).
			Msg("configuration present for an unconfigurable scanner, skipping")
	case csOK && rsOK:
		fallthrough
	case !csOK && rsOK:
		if err := rs.Configure(ctx, f, opts.Client); err != nil {
			zlog.Error(ctx).
				Str("scanner", n).
				Err(err).
				Msg("configuration failed")
			return true
		}
	case csOK && !rsOK:
		if err := cs.Configure(ctx, f); err != nil {
			zlog.Error(ctx).
				Str("scanner", n).
				Err(err).
				Msg("configuration failed")
			return true
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
	ctx = zlog.ContextWithValues(ctx,
		"component", "datastore/layerscannner/layerScanner.Scan",
		"manifest", manifest.String())

	sem := semaphore.NewWeighted(ls.inflight)
	g, ctx := errgroup.WithContext(ctx)
	// Launch is a closure to capture the loop variables and then call the
	// scanLayer method.
	launch := func(l *claircore.Layer, s indexer.VersionedScanner) func() error {
		return func() error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			defer sem.Release(1)
			return ls.scanLayer(ctx, l, s)
		}
	}
	dedupe := make(map[string]struct{})
	for _, l := range layers {
		if _, ok := dedupe[l.Hash.String()]; ok {
			continue
		}
		dedupe[l.Hash.String()] = struct{}{}
		for _, s := range ls.ps {
			g.Go(launch(l, s))
		}
		for _, s := range ls.ds {
			g.Go(launch(l, s))
		}
		for _, s := range ls.rs {
			g.Go(launch(l, s))
		}
	}

	return g.Wait()
}

// ScanLayer (along with the result type) handles an individual (scanner, layer)
// pair.
func (ls *layerScanner) scanLayer(ctx context.Context, l *claircore.Layer, s indexer.VersionedScanner) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "indexer/layerscannner/layerScanner.scan",
		"scanner", s.Name(),
		"kind", s.Kind(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("scan start")
	defer zlog.Debug(ctx).Msg("scan done")

	ok, err := ls.store.LayerScanned(ctx, l.Hash, s)
	if err != nil {
		return err
	}
	if ok {
		zlog.Debug(ctx).Msg("layer already scanned")
		return nil
	}

	var result result
	if err := result.Do(ctx, s, l); err != nil {
		return err
	}

	if err = ls.store.SetLayerScanned(ctx, l.Hash, s); err != nil {
		return fmt.Errorf("could not set layer scanned: %v", l)
	}

	return result.Store(ctx, ls.store, s, l)
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
func (r *result) Do(ctx context.Context, s indexer.VersionedScanner, l *claircore.Layer) error {
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
	if err != nil {
		zlog.Info(ctx).Err(err).Send()
	}
	return err
}

// Store calls the properly typed store method on whatever value was captured in
// the result.
func (r *result) Store(ctx context.Context, store indexer.Store, s indexer.VersionedScanner, l *claircore.Layer) error {
	switch {
	case r.pkgs != nil:
		zlog.Debug(ctx).Int("count", len(r.pkgs)).Msg("scan returned packages")
		return store.IndexPackages(ctx, r.pkgs, l, s)
	case r.dists != nil:
		zlog.Debug(ctx).Int("count", len(r.dists)).Msg("scan returned dists")
		return store.IndexDistributions(ctx, r.dists, l, s)
	case r.repos != nil:
		zlog.Debug(ctx).Int("count", len(r.repos)).Msg("scan returned repos")
		return store.IndexRepositories(ctx, r.repos, l, s)
	}
	zlog.Debug(ctx).Msg("scan returned a nil")
	return nil
}
