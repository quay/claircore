package layerscanner

import (
	"context"
	"fmt"
	"math"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"golang.org/x/sync/errgroup"

	"github.com/rs/zerolog"
)

// layerScanner implements the scanner.LayerScanner interface.
type layerScanner struct {
	// common depedencies
	*scanner.Opts
	// concurrency level. maximum number of concurrent layer scans
	cLevel int
	// a channel to implement concurrency control
	cc chan struct{}
	// a logger that can be called with context
	logger zerolog.Logger
}

// New is a constructor for a defaultLayerScanner
func New(cLevel int, opts *scanner.Opts) scanner.LayerScanner {
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
// Scan will launch all necessary go routines and each routine will block on adding a token.
// On completion a token is discarded unblocking other routines which are waiting.
//
// On ctx cancel or a go routine reporting an scan/index error all routines blocking on adding a token will error
// and the will not subsequently try to discard a token.
//
// Scan waits for all go routines to finish successfully before unblocking or returns with the first error if encountered
func (ls *layerScanner) Scan(ctx context.Context, manifest string, layers []*claircore.Layer) error {
	// compute concurrency level
	x := float64(len(layers))
	y := float64(ls.cLevel)
	if y == 0 {
		y++
	}
	ccMin := int(math.Min(x, y))

	ls.cc = make(chan struct{}, ccMin)

	ps, ds, rs, err := scanner.EcosystemsToScanners(ctx, ls.Opts.Ecosystems)
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

func (ls *layerScanner) scanPackages(ctx context.Context, layer *claircore.Layer, s scanner.PackageScanner) error {
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

	v, err := s.Scan(layer)
	if err != nil {
		return err
	}
	return ls.Store.IndexPackages(ctx, v, layer, s)
}

func (ls *layerScanner) scanDists(ctx context.Context, layer *claircore.Layer, s scanner.DistributionScanner) error {
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

	v, err := s.Scan(layer)
	if err != nil {
		return err
	}
	return ls.Store.IndexDistributions(ctx, v, layer, s)
}

func (ls *layerScanner) scanRepos(ctx context.Context, layer *claircore.Layer, s scanner.RepositoryScanner) error {
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

	v, err := s.Scan(layer)
	if err != nil {
		return err
	}
	return ls.Store.IndexRepositories(ctx, v, layer, s)
}
