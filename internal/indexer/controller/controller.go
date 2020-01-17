package controller

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// stateFunc implement the logic of our controller and map directly to States.
// returning an error will exit the controller in an error state.
// returning Terminal ends the controller in a non error state.
type stateFunc func(context.Context, *Controller) (State, error)

// States and their explanations.
// each state is implemented by a stateFunc implemented in their own files.
const (
	// Terminal is the state which halts the fsm and returns the current s.result to the caller
	Terminal State = iota
	// CheckManifest determines if the manifest should be scanned.
	// if no Terminal is returned and we return the existing IndexReport.
	// Transitions: FetchLayers, Terminal
	CheckManifest
	// FetchLayers retrieves all the layers in a manifest and stacks them the same obtain the file image contents.
	// creates the "image" layer
	// Transitions: LayerScan
	FetchLayers
	// ScanLayers scans each image including the image layer and indexes the contents
	// Transitions: BuildLayerResult
	ScanLayers
	// Coalesce runs each provided ecosystem's coalescer and mergs their scan results
	// Transitions: ScanFinished
	Coalesce
	// IndexError state indicates a impassable error has occured.
	// returns a ScanResult with the error field
	// Transitions: Terminal
	IndexError
	// IndexFinished state is the terminal state and should return a IndexReport
	// to the caller of Scan()
	// Transitions: Terminal
	IndexFinished
)

// provides a mapping of States to their implemented stateFunc methods
var stateToStateFunc = map[State]stateFunc{
	CheckManifest: checkManifest,
	FetchLayers:   fetchLayers,
	ScanLayers:    scanLayers,
	Coalesce:      coalesce,
	IndexFinished: indexFinished,
}

// StartState is a global variable which is normally set to the starting state
// of the controller. this global maybe overwriten to aide in testing. for example
// confirming that the controller does the correct thing in terminal states.
// see controller_test.go
var startState State = CheckManifest

// Controller is a control structure for scanning a manifest.
//
// Controller is implemented as an FSM.
type Controller struct {
	// holds dependencies for a indexer.controller
	*indexer.Opts
	// lock protecting State variable
	sm *sync.RWMutex
	// the current state of the controller
	currentState State
	// the manifest this controller is working on. populated on Scan() call
	manifest *claircore.Manifest
	// the result of this scan. each stateFunc manipulates this field.
	report *claircore.IndexReport
	// a fatal error halting the scanning process
	err error
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
		Opts: opts,
		sm:   &sync.RWMutex{},
		// this is a global var which maybe overwritten by tests
		currentState: startState,
		report:       scanRes,
		manifest:     &claircore.Manifest{},
	}

	return s
}

// Index kicks off an index of a particular manifest.
// Initial state set in constructor.
// Call Lock() before using and Unlock() when finished scanning.
func (s *Controller) Index(ctx context.Context, manifest *claircore.Manifest) *claircore.IndexReport {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/controller/Controller.Index").
		Str("manifest", s.manifest.Hash).
		Str("state", s.getState().String()).
		Logger()
	ctx = log.WithContext(ctx)
	// defer the removal of any tmp files if fetcher is configured for OnDisk or Tee download
	// no-op otherwise. see Fetcher for more info
	defer s.Fetcher.Close()
	// set manifest info on controller
	s.manifest = manifest
	s.report.Hash = manifest.Hash
	// setup our logger. all stateFuncs may use this to log with a log context
	log.Info().Msg("starting scan")
	s.run(ctx)
	return s.report
}

// run executes each stateFunc and blocks until either an error occurs or
// a Terminal state is encountered.
func (s *Controller) run(ctx context.Context) {
	state, err := stateToStateFunc[s.getState()](ctx, s)
	if err != nil {
		s.handleError(ctx, err)
		return
	}
	if state == Terminal {
		return
	}
	s.setState(state)
	err = s.Store.SetIndexReport(ctx, s.report)
	if err != nil {
		s.handleError(ctx, err)
		return
	}
	s.run(ctx)
}

// handleError updates the IndexReport to communicate an error and attempts
// to persist this information.
func (s *Controller) handleError(ctx context.Context, err error) {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("handling scan error")
	s.report.Success = false
	s.report.Err = err.Error()
	s.report.State = IndexError.String()
	log.Warn().
		Err(err).
		Msg("error during scan")
	err = s.Store.SetIndexReport(ctx, s.report)
	if err != nil {
		// just log, we are about to bail anyway
		log.Error().
			Err(err).
			Msg("failed to persist scan report")
	}
}

// setState is a helper method to transition the controller to the provided next state
func (s *Controller) setState(state State) {
	s.currentState = state
	s.report.State = state.String()
}

// getState is a concurrency safe method for obtaining the current state of the controller
func (s *Controller) getState() State {
	s.sm.RLock()
	ss := s.currentState
	s.sm.RUnlock()
	return ss
}

func (s *Controller) Lock(ctx context.Context, hash string) error {
	err := s.ScanLock.Lock(ctx, hash)
	if err != nil {
		return err
	}
	return nil
}

func (s *Controller) Unlock() error {
	err := s.ScanLock.Unlock()
	if err != nil {
		return err
	}
	return nil
}
