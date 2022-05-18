package controller

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Controller is a control structure for scanning a manifest.
//
// Controller is implemented as an FSM.
type Controller struct {
	// holds dependencies for a indexer.controller
	*indexer.Opts
	// the manifest this controller is working on. populated on Scan() call
	manifest *claircore.Manifest
	// the result of this scan. each stateFunc manipulates this field.
	report *claircore.IndexReport
	// a fatal error halting the scanning process
	err error
	// the current state of the controller
	currentState State
}

// New constructs a controller given an Opts struct
func New(opts *indexer.Opts) *Controller {
	// fully init any maps and arrays
	scanRes := &claircore.IndexReport{
		Packages:      map[string]*claircore.Package{},
		Environments:  map[string][]*claircore.Environment{},
		Distributions: map[string]*claircore.Distribution{},
		Repositories:  map[string]*claircore.Repository{},
	}

	s := &Controller{
		Opts:         opts,
		currentState: CheckManifest,
		report:       scanRes,
		manifest:     &claircore.Manifest{},
	}

	return s
}

// Index kicks off an index of a particular manifest.
// Initial state set in constructor.
func (s *Controller) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// set manifest info on controller
	s.manifest = manifest
	s.report.Hash = manifest.Hash
	ctx = zlog.ContextWithValues(ctx,
		"component", "indexer/controller/Controller.Index",
		"manifest", s.manifest.Hash.String())
	defer s.Realizer.Close()
	zlog.Info(ctx).Msg("starting scan")
	return s.report, s.run(ctx)
}

// Run executes each stateFunc and blocks until either an error occurs or a
// Terminal state is encountered.
func (s *Controller) run(ctx context.Context) (err error) {
	var next State
	var retry bool
	var w time.Duration

	// As long as there's not an error and the current state isn't Terminal, run
	// the corresponding function.
	for err == nil && s.currentState != Terminal {
		ctx := zlog.ContextWithValues(ctx, "state", s.currentState.String())
		next, err = stateToStateFunc[s.currentState](ctx, s)
		switch {
		case errors.Is(err, nil) && !errors.Is(ctx.Err(), nil):
			// If the passed-in context reports an error, drop out of the loop.
			// This is an odd state but not impossible: a deadline could time
			// out while returning from the call above.
			//
			// In all the other switch arms, we now know that the parent context
			// is OK.
			err = ctx.Err()
			continue
		case errors.Is(err, nil):
			// OK
		case errors.Is(err, context.DeadlineExceeded):
			// Either the function's internal deadline or the parent's deadline
			// was hit.
			retry = true
		case errors.Is(err, context.Canceled):
			// The parent context was canceled and the stateFunc noticed.
			// Continuing the loop should drop execution out of it.
			continue
		default:
			s.setState(IndexError)
			zlog.Error(ctx).
				Err(err).
				Msg("error during scan")
			s.report.Success = false
			s.report.Err = err.Error()
		}
		if err := s.Store.SetIndexReport(ctx, s.report); !errors.Is(err, nil) {
			zlog.Info(ctx).
				Err(err).
				Msg("failed persisting index report")
		}
		if retry {
			t := time.NewTimer(w)
			select {
			case <-ctx.Done():
			case <-t.C:
			}
			t.Stop()
			w = jitter()
			retry = false
			// Execution is in this conditional because err ==
			// context.DeadlineExceeded, so reset the err value to make sure the
			// loop makes it back to the error handling switch above. If the
			// context was canceled, the loop will end there; if not, there will
			// be a retry.
			err = nil
		}
		// This if statement preserves current behaviour of not setting
		// currentState to Terminal when it's returned. This should be an
		// internal detail, but is codified in the tests (for now).
		if next == Terminal {
			break
		}
		s.setState(next)
	}
	if err != nil {
		return err
	}
	return nil
}

// setState is a helper method to transition the controller to the provided next state
func (s *Controller) setState(state State) {
	s.currentState = state
	s.report.State = state.String()
}

// Jitter produces a duration of at least 1 second and no more than 5 seconds.
func jitter() time.Duration {
	return time.Duration(1000+rand.Intn(4000)) * time.Millisecond
}
