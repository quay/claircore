package layerscanner

import (
	"context"
	"fmt"
	"math"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// layerScanner implements the indexer.LayerScanner interface.
type layerScanner struct {
	// common depedencies
	*indexer.Opts
	// concurrency level. maximum number of concurrent layer scans
	cLevel int
	// a channel to implement concurrency control
	cc chan struct{}
}

// New is a constructor for a defaultLayerScanner
func New(cLevel int, opts *indexer.Opts) indexer.LayerScanner {
	return &layerScanner{
		Opts:   opts,
		cLevel: cLevel,
	}
}

// addToken will block until a spot in the conccurency channel is available
// or the ctx is canceled.
func (ls *layerScanner) addToken(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ls.cc <- struct{}{}:
		return nil
	}
}

// discardToken is only called after addToken. Removes a token
// from the concurrency channel allowing another task to kick off.
func (ls *layerScanner) discardToken() {
	select {
	case <-ls.cc:
	default:
	}
}

// Scan performs a concurrency controlled scan of each layer by each type of configured scanner, indexing
// the results on successful completion.
//
// Scan will launch all pending layer scans in a Go routine.
// Scan will ensure only 'cLevel' routines are actively scanning layers.
//
// If the provided ctx is canceled all routines are canceled and an error will be returned.
// If one or more layer scans fail Scan will report the first received error and all pending and inflight scans will be canceled.
func (ls *layerScanner) Scan(ctx context.Context, manifest string, layers []*claircore.Layer) error {
	// compute concurrency level
	x := float64(len(layers))
	y := float64(ls.cLevel)
	if y == 0 {
		y++
	}
	ccMin := int(math.Min(x, y))

	ls.cc = make(chan struct{}, ccMin)

	ps, ds, rs, err := indexer.EcosystemsToScanners(ctx, ls.Opts.Ecosystems)
	if err != nil {
		fmt.Errorf("failed to extract scanners from ecosystems: %v", err)
	}

	g, gctx := errgroup.WithContext(ctx)
	for _, layer := range layers {
		ll := layer

		for _, s := range ps {
			ss := s
			g.Go(func() error {
				return ls.scanPackages(gctx, ll, ss)
			})
		}

		for _, s := range ds {
			ss := s
			g.Go(func() error {
				return ls.scanDists(gctx, ll, ss)
			})
		}

		for _, s := range rs {
			ss := s
			g.Go(func() error {
				return ls.scanRepos(gctx, ll, ss)
			})
		}
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (ls *layerScanner) scanPackages(ctx context.Context, layer *claircore.Layer, s indexer.PackageScanner) error {
	if err := ls.addToken(ctx); err != nil {
		return err
	}
	defer ls.discardToken()

	ok, err := ls.Store.LayerScanned(ctx, layer.Hash, s)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	v, err := s.Scan(ctx, layer)
	if err != nil {
		return fmt.Errorf("scanner: %v error: %v", s.Name(), err)
	}
	return ls.Store.IndexPackages(ctx, v, layer, s)
}

func (ls *layerScanner) scanDists(ctx context.Context, layer *claircore.Layer, s indexer.DistributionScanner) error {
	if err := ls.addToken(ctx); err != nil {
		return err
	}
	defer ls.discardToken()

	ok, err := ls.Store.LayerScanned(ctx, layer.Hash, s)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	v, err := s.Scan(ctx, layer)
	if err != nil {
		return fmt.Errorf("scanner: %v error: %v", s.Name(), err)
	}
	return ls.Store.IndexDistributions(ctx, v, layer, s)
}

func (ls *layerScanner) scanRepos(ctx context.Context, layer *claircore.Layer, s indexer.RepositoryScanner) error {
	if err := ls.addToken(ctx); err != nil {
		return err
	}
	defer ls.discardToken()

	ok, err := ls.Store.LayerScanned(ctx, layer.Hash, s)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	v, err := s.Scan(ctx, layer)
	if err != nil {
		return fmt.Errorf("scanner: %v error: %v", s.Name(), err)
	}
	return ls.Store.IndexRepositories(ctx, v, layer, s)
}
