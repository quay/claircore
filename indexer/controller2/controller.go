package controller

import (
	"context"
	"fmt"
	"runtime"
	"runtime/trace"

	"github.com/quay/zlog"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Options contains the options needed to construct a [Controller].
type Options struct {
	// The following are shared components between [Controller.Index] calls.
	Store        indexer.Store
	LayerIndexer indexer.LayerScanner
	Realizer     func(context.Context) (indexer.Realizer, error)
	Ecosystems   []indexer.Ecosystem
	Indexers     []indexer.VersionedScanner
	// Limit is the number of concurrent allowed calls to [Controller.Index].
	//
	// If set to 0, [runtime.GOMAXPROCS] will be used. If set to a negative
	// number, [math.MaxInt64] will be used.
	Limit int64
}

// Controller drives the indexer state machine.
type Controller struct {
	store        indexer.Store
	layerIndexer indexer.LayerScanner
	newRealizer  func(context.Context) (indexer.Realizer, error)
	sem          *semaphore.Weighted
	ecosystems   []indexer.Ecosystem
	indexers     []indexer.VersionedScanner
}

// New constructs a Controller with the given Options.
//
// The Controller should be re-used for [Index] calls, unlike previous
// versions of this package. The caller may panic if the [Close]
// method is not called.
func New(opts Options) (*Controller, error) {
	lim := opts.Limit
	switch {
	case lim < 1:
		lim = 1<<63 - 1
	case lim == 0:
		lim = int64(runtime.GOMAXPROCS(0))
	}
	c := &Controller{
		store:        opts.Store,
		ecosystems:   opts.Ecosystems,
		indexers:     opts.Indexers,
		newRealizer:  opts.Realizer,
		layerIndexer: opts.LayerIndexer,
		sem:          semaphore.NewWeighted(lim),
	}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(c, func(c *Controller) {
		panic(fmt.Sprintf("%s:%d: Controller not closed", file, line))
	})
	return c, nil
}

// Index kicks off an index of a particular Manifest.
func (c *Controller) Index(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
	const taskType = `indexer/controller/Controller.Index`
	ctx, task := trace.NewTask(ctx, taskType)
	defer task.End()
	trace.Log(ctx, "manifest", m.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", taskType,
		"manifest", m.Hash.String())
	if err := c.sem.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("controller: unable to acquire semaphore: %w", err)
	}
	defer c.sem.Release(1)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("controller: context already expired: %w", err)
	}

	r, err := c.newRealizer(ctx)
	if err != nil {
		return nil, fmt.Errorf("controller: unable to create new realizer: %w", err)
	}
	defer r.Close()

	s := &indexState{
		Store:        c.store,
		Ecosystems:   c.ecosystems,
		Indexers:     c.indexers,
		Realizer:     r,
		LayerIndexer: c.layerIndexer,
	}
	s.Manifest = m
	stateProf.Add(s, 0)
	defer stateProf.Remove(s)
	zlog.Info(ctx).Msg("index start")
	defer zlog.Info(ctx).Msg("index done")
	return s.Out, s.run(ctx)
}

// Close releases any associated resources.
func (c *Controller) Close() error {
	runtime.SetFinalizer(c, nil)
	return nil
}

// NewIndexReport constructs an [claircore.IndexReport].
func newIndexReport(d claircore.Digest) *claircore.IndexReport {
	return &claircore.IndexReport{
		Hash:          d,
		Packages:      map[string]*claircore.Package{},
		Environments:  map[string][]*claircore.Environment{},
		Distributions: map[string]*claircore.Distribution{},
		Repositories:  map[string]*claircore.Repository{},
	}
}
