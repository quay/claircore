package controller

import (
	"context"
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// stateFunc implement the logic of our controller and map directly to ScannerStates.
// returnin an error will exit the scanner in an error state.
// returning Terminal ends the scanner in a non error state.
// type stateFunc func(*defaultScanner, context.Context) (ScannerState, error)
type stateFunc func(context.Context, *Controller) (State, error)

// States and their explanations.
// each state is implemented by a stateFunc implemented in their own files.
const (
	// Terminal is the state which halts the fsm and returns the current s.result to the caller
	Terminal State = iota
	// CheckManifest determines if the manifest should be scanned.
	// if no Terminal is returned and we return the existing ScanReport.
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
	// ScanError state indicates a impassable error has occured.
	// returns a ScanResult with the error field
	// Transitions: Terminal
	ScanError
	// ScanFinished state is the terminal state and should return a ScanReport
	// to the caller of Scan()
	// Transitions: Terminal
	ScanFinished
)

// provides a mapping of States to their implemented stateFunc methods
var stateToStateFunc = map[State]stateFunc{
	CheckManifest: checkManifest,
	FetchLayers:   fetchLayers,
	ScanLayers:    scanLayers,
	Coalesce:      coalesce,
	ScanFinished:  scanFinished,
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
	// holds dependencies for a scanner.controller
	*scanner.Opts
	// lock protecting State variable
	sm *sync.RWMutex
	// the current state of the controller
	currentState State
	// the manifest this controller is working on. populated on Scan() call
	manifest *claircore.Manifest
	// the result of this scan. each stateFunc manipulates this field.
	report *claircore.ScanReport
	// a fatal error halting the scanning process
	err error
	// a logger with context. set on Scan() method call
	logger zerolog.Logger
}

// New constructs a controller given an Opts struct
func New(opts *scanner.Opts) *Controller {
	// fully init any maps and arrays
	scanRes := &claircore.ScanReport{
		PackageIntroduced:     map[int]string{},
		Packages:              map[int]*claircore.Package{},
		Distributions:         map[int]*claircore.Distribution{},
		Repositories:          map[int]*claircore.Repository{},
		DistributionByPackage: map[int]int{},
		RepositoryByPackage:   map[int]int{},
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

// Scan kicks off a scan of a particular manifest.
// Initial state set in constructor.
// Call Lock() before using and Unlock() when finished scanning.
func (s *Controller) Scan(ctx context.Context, manifest *claircore.Manifest) *claircore.ScanReport {
	// defer the removal of any tmp files if fetcher is configured for OnDisk or Tee download
	// no-op otherwise. see Fetcher for more info
	defer s.Fetcher.Purge()

	// set manifest info on controller
	s.manifest = manifest
	s.report.Hash = manifest.Hash

	// setup our logger. all stateFuncs may use this to log with a log context
	s.logger = log.With().Str("component", "scan-controller").Str("manifest", s.manifest.Hash).Logger()
	s.logger.Info().Str("state", s.getState().String()).Msg("starting scan")

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
	err = s.Store.SetScanReport(ctx, s.report)
	if err != nil {
		s.handleError(ctx, err)
		return
	}

	s.run(ctx)
}

// handleError updates the ScanReport to communicate an error and attempts
// to persist this information.
func (s *Controller) handleError(ctx context.Context, err error) {
	s.logger.Error().Str("state", s.getState().String()).Msg("handling scan error")
	s.report.Success = false
	s.report.Err = err.Error()
	s.report.State = ScanError.String()
	s.logger.Err(err).Msgf("countered error during scan: %v", err)
	err = s.Store.SetScanReport(ctx, s.report)
	if err != nil {
		// just log, we are about to bail anyway
		s.logger.Error().Msgf("failed to push scan report when handling error: %v", err)
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
