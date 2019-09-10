package defaultlayerscanner

import (
	"context"
	"fmt"
	"math"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// defaultLayerScanner implements the libscan.LayerScanner interface.
type defaultLayerScanner struct {
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
	return &defaultLayerScanner{
		Opts:   opts,
		cLevel: cLevel,
	}
}

// Scan performs max cLevel concurrent scans of the provided layers.
func (ls *defaultLayerScanner) Scan(ctx context.Context, manifest string, layers []*claircore.Layer) error {
	// create concurrency control channel.
	// if ls.LayerScanConcurrency is 0 bump to 1; pick min of both values
	x := float64(len(layers))
	y := float64(ls.cLevel)
	if y == 0 {
		y++
	}

	ccMin := int(math.Min(x, y))
	ls.cc = make(chan struct{}, ccMin)

	// setup logger context
	ls.logger = log.With().Str("component", "defaultLayerScanner").Str("manifest", manifest).Int("concurrency", ccMin).Logger()

	ls.logger.Info().Msg("starting concurrent layer scan")
	var g errgroup.Group
	for _, l := range layers {
		err := ls.addToken(ctx)
		if err != nil {
			return err
		}

		// make a copy of our layer point before providing to the go routine. we do not
		// want to share the l variable as this will cause a data race
		ll := l
		g.Go(func() error {
			// discarding a token allows another scan to occur if concurrency limit was reached
			defer ls.discardToken()
			// scan packages
			err := ls.scanPackages(ctx, ll)
			return err
		})
	}

	// wait for any concurrent scans to finish
	if err := g.Wait(); err != nil {
		return fmt.Errorf("encountered error while scanning a layer: %v", err)
	}
	return nil
}

func (ls *defaultLayerScanner) scanPackages(ctx context.Context, layer *claircore.Layer) error {
	for _, scnr := range ls.PackageScanners {
		// confirm if we have scanned this layer with this scanner before
		if ok, _ := ls.Store.LayerScanned(layer.Hash, scnr); ok {
			ls.logger.Debug().Msgf("layer %s already scanned by %v", layer.Hash, scnr)
			continue
		}

		// scan layer with current scanner
		ls.logger.Debug().Msgf("scanning layer %s scr: %v", layer.Hash, scnr.Name())
		pkgs, err := scnr.Scan(layer)
		if err != nil {
			ls.logger.Error().Msgf("scr %v reported an error for layer %v: %v", scnr.Name(), layer.Hash, err)
			return fmt.Errorf("scr %v reported an error for layer %v: %v", scnr.Name(), layer.Hash, err)
		}

		err = ls.Store.IndexPackages(pkgs, layer, scnr)
		if err != nil {
			ls.logger.Error().Msgf("failed to index packages for layer %v scr: %v: %v", layer.Hash, scnr, err)
			return fmt.Errorf("failed to index packages for layer %v and scanner %v: %v", layer.Hash, scnr, err)
		}
	}
	return nil
}

// addToken will block if concurrency limit is hit.
func (ls *defaultLayerScanner) addToken(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ls.cc <- struct{}{}:
		return nil
	}
}

// discardToken removes a token from the concurrency channel
func (ls *defaultLayerScanner) discardToken() {
	<-ls.cc
}
