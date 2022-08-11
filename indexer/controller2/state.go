package controller

import (
	"context"
	"errors"
	"math/rand"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// StateProf is a profile collecting indexState objects.
var stateProf = pprof.NewProfile("github.com/quay/claircore/indexer/controller2.indexState")

// IndexState is the bundle of state for the indexer state machine.
type indexState struct {
	Store        indexer.Store
	Realizer     indexer.Realizer
	LayerIndexer indexer.LayerScanner
	Err          error
	Manifest     *claircore.Manifest
	Out          *claircore.IndexReport
	Ecosystems   []indexer.Ecosystem
	Indexers     []indexer.VersionedScanner
}

// StateFn is the self-referential type for each state the indexer is in.
//
// Nil is the terminal state. States should use the [indexState.error] method
// to set an error return.
type stateFn func(context.Context, *indexState) stateFn

// Run runs indexer state machine.
//
// The initial state is "CheckManifest".
func (s *indexState) run(ctx context.Context) error {
	var retry bool
	var w time.Duration

	// As long as there's not an error and the current state isn't Terminal, run
	// the corresponding function.
	for f := _CheckManifest; f != nil; pace(ctx, retry, &w) {
		name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
		name = name[strings.LastIndexByte(name, '.'):]
		name = strings.TrimLeft(name, "._")
		f = f(zlog.ContextWithValues(ctx, "state", name), s)
		switch {
		case errors.Is(s.Err, nil) && !errors.Is(ctx.Err(), nil):
			// If the passed-in context reports an error, drop out of the loop.
			// This is an odd state but not impossible: a deadline could time
			// out while returning from the call above.
			//
			// In all the other switch arms, we now know that the parent context
			// is OK.
			s.Err = ctx.Err()
			continue
		case errors.Is(s.Err, nil):
			// OK
		case errors.Is(s.Err, context.DeadlineExceeded):
			// Either the function's internal deadline or the parent's deadline
			// was hit.
			fallthrough
		case errors.Is(s.Err, errRetry):
			retry = true
		case errors.Is(s.Err, context.Canceled):
			// The parent context was canceled and the stateFunc noticed.
			// Continuing the loop should drop execution out of it.
			continue
		default:
			zlog.Error(ctx).
				Err(s.Err).
				Msg("error during index")
			s.Out.Success = false
			s.Out.Err = s.Err.Error()
		}
		s.Out.State = name
		if err := s.Store.SetIndexReport(ctx, s.Out); !errors.Is(err, nil) {
			zlog.Info(ctx).
				Err(err).
				Msg("failed persisting index report")
		}
	}
	return s.Err
}

// Error records the provided error and returns a terminal stateFn.
func (s *indexState) error(ctx context.Context, err error) stateFn {
	s.Err = err
	return nil
}

// Retry marks an error as retryable and returns the passed stateFn.
func (s *indexState) retry(ctx context.Context, state stateFn, err error) stateFn {
	s.Err = markRetryable(err)
	return state
}

// Pace is a helper to pace iterations around a loop.
//
// The value pointed to by "dur" is used and then reset to a new random value.
func pace(ctx context.Context, retry bool, dur *time.Duration) {
	if !retry {
		return
	}
	t := time.NewTimer(*dur)
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	t.Stop()
	*dur = time.Duration(1000+rand.Intn(4000)) * time.Millisecond
}
