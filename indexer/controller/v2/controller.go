package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

type Controller struct {
	store   indexer.Store // NOTE(hank) This should be [datastore.Indexer].
	fetcher indexer.FetchArena
}

func New(ctx context.Context,
	store indexer.Store,
	fetcher indexer.FetchArena,
) (*Controller, error) {
	c := Controller{
		store:   store,
		fetcher: fetcher,
	}
	return &c, nil
}

func (c *Controller) Index(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
	e, err := c.newExec(ctx)
	if err != nil {
		return nil, fmt.Errorf("controller: unable to construct execution context: %w", err)
	}
	defer func() {
		if err := e.Close(); err != nil {
			zlog.Info(ctx).
				Err(err).
				Msg("error closing resources")
		}
	}()

Run:
	for !e.IsTerminal() {
		// At the start of every step, check if the request's context is valid.
		// If not, everything should be at a safe-point and we can just exit this loop.
		select {
		case <-ctx.Done():
			err = context.Cause(ctx)
			// Break directly to avoid messing with the exec struct.
			break Run
		default:
		}

		// Run this step.
		// The execution should continue as long as the parent context is valid
		// or a short interval after the parent context was canceled, whichever
		// is longer.
		func() {
			ctx := zlog.ContextWithValues(ctx, "step", e.State.String())
			defer func() {
				zlog.Debug(ctx).
					Err(err).
					Stringer("next", e.State).
					Msg("step ran")
			}()

			// Create & cleanup the step context.
			sctx, cause := context.WithCancelCause(context.WithoutCancel(ctx))
			stop := context.AfterFunc(ctx, func() { // NB Using the parent context.
				time.Sleep(30 * time.Second) // BUG(hank) The per-step grace period is not configurable.
				cause(fmt.Errorf("controller: %w: %w", errGracePeriod, context.Cause(ctx)))
			})
			defer func() {
				// This is complicated because of the desired grace period behavior.
				usedGrace := !stop()
				err := sctx.Err() // Make sure to capture this before the unconditional CancelCause call.
				cause(errStepComplete)
				zlog.Debug(ctx).
					Bool("used_grace_period", usedGrace).
					Bool("timed_out", errors.Is(err, errGracePeriod)).
					AnErr("cause", err).
					Msg("ending step context")
			}()

			e.State, err = e.State(sctx, e, m)
		}()

		// All errors out of controller steps should either be of type *stepError,
		// or be accompanied by a terminal stateFn.
		var serr *stepError
		switch {
		case errors.Is(err, nil):
		case errors.As(err, &serr):
			panic("TODO: handle stepErr")
		case e.IsTerminal():
			// "Err" is not a *stepErr and is was with a terminal stateFn.
			continue
		default:
			panic(fmt.Errorf("programmer error: previous step returned (%v, %v) ", e.State, err))
		}

		// TODO(hank) Do the database persistence.
	}
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, context.Canceled):
		// Log?
		return nil, fmt.Errorf("controller: ended early: %w", err)
	default:
		return nil, fmt.Errorf("controller: fatal error: %w", err)
	}

	return e.Result, nil
}

func (c *Controller) newExec(ctx context.Context) (*exec, error) {
	e := exec{
		Store:    c.store,
		Realizer: c.fetcher.Realizer(ctx).(indexer.DescriptionRealizer),

		Result: &claircore.IndexReport{
			Packages:      map[string]*claircore.Package{},
			Environments:  map[string][]*claircore.Environment{},
			Distributions: map[string]*claircore.Distribution{},
			Repositories:  map[string]*claircore.Repository{},
			Files:         map[string]claircore.File{},
		},
		State: checkManifest,
	}
	return &e, nil
}

type stateFn func(context.Context, *exec, *claircore.Manifest) (stateFn, error)

func (f stateFn) String() (n string) {
	if f == nil {
		return "<Terminal>"
	}
	n = runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	_, n, _ = strings.Cut(n, "controller.")
	return n
}

// Aliases for my sanity
type detector = indexer.VersionedScanner
type store = indexer.Store // Should be [datastore.Indexer]

type exec struct {
	Store     store
	Detectors []detector
	Realizer  indexer.DescriptionRealizer

	Defer  []io.Closer
	Result *claircore.IndexReport
	State  stateFn
}

func (e *exec) IsTerminal() bool {
	return e.State == nil
}

func (e *exec) Close() error {
	errs := make([]error, len(e.Defer)+1)
	for i, c := range e.Defer {
		errs[i] = c.Close()
	}
	errs[len(errs)-1] = e.Realizer.Close()
	return errors.Join(errs...)
}
