package indexer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"

	"github.com/quay/claircore/toolkit/log"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
)

type LayerScanner struct {
	store Store

	// Maximum allowed in-flight scanners per Scan call
	inflight int

	// Pre-constructed and configured scanners.
	ps  []PackageScanner
	ds  []DistributionScanner
	rs  []RepositoryScanner
	fis []FileScanner
}

// NewLayerScanner is the constructor for a LayerScanner.
//
// The provided Context is only used for the duration of the call.
func NewLayerScanner(ctx context.Context, concurrent int, opts *Options) (*LayerScanner, error) {
	slog.InfoContext(ctx, "constructing")
	switch {
	case concurrent < 1:
		slog.WarnContext(ctx, "rectifying nonsense 'concurrent' argument", "value", concurrent)
		fallthrough
	case concurrent == 0:
		concurrent = runtime.GOMAXPROCS(0)
	}

	ps, ds, rs, fs, err := EcosystemsToScanners(ctx, opts.Ecosystems)
	if err != nil {
		return nil, fmt.Errorf("failed to extract scanners from ecosystems: %v", err)
	}

	return &LayerScanner{
		store:    opts.Store,
		inflight: concurrent,
		ps:       configAndFilter(ctx, opts, ps),
		ds:       configAndFilter(ctx, opts, ds),
		rs:       configAndFilter(ctx, opts, rs),
		fis:      configAndFilter(ctx, opts, fs),
	}, nil
}

func configAndFilter[S VersionedScanner](ctx context.Context, opts *Options, ss []S) []S {
	i := 0
	for _, s := range ss {
		n := s.Name()
		log := slog.With("scanner", n)
		var cfgMap map[string]func(any) error
		switch k := s.Kind(); k {
		case "package":
			cfgMap = opts.ScannerConfig.Package
		case "repository":
			cfgMap = opts.ScannerConfig.Repo
		case "distribution":
			cfgMap = opts.ScannerConfig.Dist
		case "file":
			cfgMap = opts.ScannerConfig.File
		default:
			log.WarnContext(ctx, "unknown scanner kind", "kind", k)
			continue
		}

		f, haveCfg := cfgMap[n]
		if !haveCfg {
			f = func(any) error { return nil }
		}
		cs, csOK := any(s).(ConfigurableScanner)
		rs, rsOK := any(s).(RPCScanner)
		switch {
		case haveCfg && !csOK && !rsOK:
			log.WarnContext(ctx, "configuration present for an unconfigurable scanner, skipping")
		case csOK && rsOK:
			fallthrough
		case !csOK && rsOK:
			if err := rs.Configure(ctx, f, opts.Client); err != nil {
				log.ErrorContext(ctx, "configuration failed", "reason", err)
				continue
			}
		case csOK && !rsOK:
			if err := cs.Configure(ctx, f); err != nil {
				log.ErrorContext(ctx, "configuration failed", "reason", err)
				continue
			}
		}
		ss[i] = s
		i++
	}
	ss = ss[:i]
	return ss
}

// Scan performs a concurrency controlled scan of each layer by each configured
// scanner, indexing the results on successful completion.
//
// Scan will launch all layer scan goroutines immediately and then only allow
// the configured limit to proceed.
//
// The provided Context controls cancellation for all scanners. The first error
// reported halts all work and is returned from Scan.
func (ls *LayerScanner) Scan(ctx context.Context, manifest claircore.Digest, layers []*claircore.Layer) error {
	ctx = log.With(ctx, "manifest", manifest)

	g, ctx := errgroup.WithContext(ctx)
	// Using the goroutine's built-in limit is worst-case the same as using an
	// external semaphore (spawn N goroutines and immediately wait on M of them,
	// waits canceling when the first error is returned) but putting the
	// Context check in the "Layers" loop means we only spawn max 3 extra goroutines
	// that will immediately return.
	g.SetLimit(ls.inflight)
	// Launch is a closure to capture the loop variables and then call the
	// scanLayer method.
	launch := func(l *claircore.Layer, s VersionedScanner) func() error {
		return func() error {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			default:
			}
			if err := ls.scanLayer(ctx, l, s); err != nil {
				return fmt.Errorf("layer %q: %w", l.Hash, err)
			}
			return nil
		}
	}
	dedupe := make(map[string]struct{})
Layers:
	for _, l := range layers {
		select {
		case <-ctx.Done():
			break Layers
		default:
		}
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
		for _, s := range ls.fis {
			g.Go(launch(l, s))
		}
	}

	return g.Wait()
}

// ScanLayer (along with the result type) handles an individual (scanner, layer)
// pair.
func (ls *LayerScanner) scanLayer(ctx context.Context, l *claircore.Layer, s VersionedScanner) error {
	ctx = log.With(ctx, "scanner", s.Name(), "kind", s.Kind(), "layer", l.Hash)
	slog.DebugContext(ctx, "scan start")
	defer slog.DebugContext(ctx, "scan done")

	ok, err := ls.store.LayerScanned(ctx, l.Hash, s)
	if err != nil {
		return err
	}
	if ok {
		slog.DebugContext(ctx, "layer already scanned")
		return nil
	}

	var result result
	if err := result.Do(ctx, s, l); err != nil {
		return err
	}

	if err = result.Store(ctx, ls.store, s, l); err != nil {
		return err
	}

	if err = ls.store.SetLayerScanned(ctx, l.Hash, s); err != nil {
		return fmt.Errorf("could not set layer scanned: %w", err)
	}

	return nil
}

// Result is a type that handles the kind-specific bits of the scan process.
type result struct {
	pkgs  []*claircore.Package
	dists []*claircore.Distribution
	repos []*claircore.Repository
	files []claircore.File
}

// Do asserts the Scanner back to having a Scan method, and then calls it.
//
// The success value is captured and the error value is returned by Do.
func (r *result) Do(ctx context.Context, s VersionedScanner, l *claircore.Layer) error {
	var err error
	switch s := s.(type) {
	case PackageScanner:
		r.pkgs, err = s.Scan(ctx, l)
		if sc, ok := s.(DefaultRepoScanner); ok {
			if len(r.pkgs) > 0 {
				r.repos = append(r.repos, sc.DefaultRepository(ctx))
			}
		}
	case DistributionScanner:
		r.dists, err = s.Scan(ctx, l)
	case RepositoryScanner:
		r.repos, err = s.Scan(ctx, l)
	case FileScanner:
		r.files, err = s.Scan(ctx, l)
	default:
		panic(fmt.Sprintf("programmer error: unknown type %T used as scanner", s))
	}

	var addrErr *net.AddrError
	switch {
	case errors.Is(err, nil):
	case errors.As(err, &addrErr):
		slog.WarnContext(ctx, "scanner not able to access resources", "scanner", s.Name(), "reason", err)
		return nil
	default:
		slog.InfoContext(ctx, "unexpected error", "reason", err)
	}

	return err
}

// Store calls the properly typed store method on whatever value was captured in
// the result.
func (r *result) Store(ctx context.Context, store Store, s VersionedScanner, l *claircore.Layer) error {
	if r.pkgs != nil {
		slog.DebugContext(ctx, "scan returned packages", "count", len(r.pkgs))
		if err := store.IndexPackages(ctx, r.pkgs, l, s); err != nil {
			return err
		}
	}
	if r.dists != nil {
		slog.DebugContext(ctx, "scan returned distributions", "count", len(r.dists))
		if err := store.IndexDistributions(ctx, r.dists, l, s); err != nil {
			return err
		}
	}
	if r.repos != nil {
		slog.DebugContext(ctx, "scan returned repositories", "count", len(r.repos))
		if err := store.IndexRepositories(ctx, r.repos, l, s); err != nil {
			return err
		}
	}
	if r.files != nil {
		slog.DebugContext(ctx, "scan returned files", "count", len(r.files))
		if err := store.IndexFiles(ctx, r.files, l, s); err != nil {
			return err
		}
	}
	return nil
}
