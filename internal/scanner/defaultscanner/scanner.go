package defaultscanner

import (
	"context"
	"sync"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/scanner"
	"github.com/quay/claircore/pkg/distlock"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// stateFunc implement the logic of our scanner and map directly to ScannerStates.
// returnin an error will exit the scanner in an error state.
// returning Terminal ends the scanner in a non error state.
type stateFunc func(*defaultScanner, context.Context) (ScannerState, error)

// States and their explanations.
// each state is implemented by a stateFunc implemented in their own files.
const (
	// Terminal is the state which halts the fsm and returns the current s.result to the caller
	Terminal ScannerState = iota
	// CheckManifest determines if the manifest should be scanned.
	// if no Terminal is returned and we return the existing ScanReport.
	// Transitions: FetchAndStackLayers, Terminal
	CheckManifest
	// FetchAndStackLayers retrieves all the layers in a manifest and stacks them the same obtain the file image contents.
	// creates the "image" layer
	// Transitions: LayerScan
	FetchAndStackLayers
	// LayerScan scans each image including the image layer and indexes the contents
	// Transitions: BuildLayerResult
	LayerScan
	// BuildImageResult inventories the discovered packages in the image layer
	// Transitions BuildLayerResult
	BuildImageResult
	// BuildLayerResult finds the layer a package was introduced in
	// Transitions: ScanError
	BuildLayerResult
	// ScanError state indicates a impassable error has occured.
	// returns a ScanResult with the error field
	// Transitions: Terminal
	ScanError
	// ScanFinished state is the terminal state and should return a ScanReport
	// to the caller of Scan()
	// Transitions: Terminal
	ScanFinished
)

// provides a mapping of ScannerStates to their implemented stateFunc methods
var stateToStateFunc = map[ScannerState]stateFunc{
	CheckManifest:       checkManifest,
	FetchAndStackLayers: fetchAndStackLayers,
	LayerScan:           layerScan,
	BuildImageResult:    buildImageResult,
	BuildLayerResult:    buildLayerResult,
	ScanFinished:        scanFinished,
}

// StartState is a global variable which is normally set to the starting state
// of the scanner. this global maybe overwriten to aide in testing. for example
// confirming that the scanner does the correct thing in terminal states.
// see scanner_test.go
var startState ScannerState = CheckManifest

// defaultScanner implements the scanner.Scanner interface.
// not safe for reuse or sharing
type defaultScanner struct {
	*scanner.Opts
	// lock protecting State variable
	sm *sync.RWMutex
	// the current state of the scanner
	currentState ScannerState
	// the manifest this *defaultScanner is working on. populated on Scan() call
	manifest *claircore.Manifest
	// the result of this scan. each stateFunc manipulates this field.
	report *claircore.ScanReport
	// a synethic layer representing the container's final stacked filesystem contents.
	imageLayer *claircore.Layer
	// a distributed lock which should be locked before the Scan() method and Unlocked()
	// after the scan completes. we leave this up to the caller so to not dig the locking
	// and unlocking logic between state transitions.
	distLock distlock.Locker
	// a fatal error halting the scanning process
	err error
	// a convenience field holding all configured scanners as VersionedScanner interfaces
	vscnrs scanner.VersionedScanners
	// a logger with context. set on Scan() method call
	logger zerolog.Logger
}

// NewScanner constructs a scanner given an Opts struct
func New(opts *scanner.Opts) *defaultScanner {
	// fully init any maps and arrays
	scanRes := &claircore.ScanReport{
		PackageIntroduced: map[int]string{},
		Packages:          map[int]*claircore.Package{},
	}

	// convert PackageScanners to VersionedScanners for convenience. most Store methods expect these
	// to be generic.
	var vscnrs scanner.VersionedScanners
	vscnrs.PStoVS(opts.PackageScanners)

	s := &defaultScanner{
		Opts: opts,
		sm:   &sync.RWMutex{},
		// this is a global var which maybe overwritten by tests
		currentState: startState,
		report:       scanRes,
		manifest:     &claircore.Manifest{},
		vscnrs:       vscnrs,
		distLock:     opts.ScanLock,
	}

	return s
}

// Scan kicks off a scan of a particular manifest.
// Initial state set in constructor.
// Call Lock() before using and Unlock() when finished scanning.
func (s *defaultScanner) Scan(ctx context.Context, manifest *claircore.Manifest) *claircore.ScanReport {
	// defer the removal of any tmp files if fetcher is configured for OnDisk or Tee download
	// no-op otherwise. see Fetcher for more info
	defer s.Fetcher.Purge()

	// set manifest info on scanner
	s.manifest = manifest
	s.report.Hash = manifest.Hash

	// setup our logger. all stateFuncs may use this to log with a log context
	s.logger = log.With().Str("component", "defaultScanner").Str("manifest", s.manifest.Hash).Logger()
	s.logger.Info().Str("state", s.getState().String()).Msg("starting scan")

	s.run(ctx)

	return s.report
}

// run executes each stateFunc and blocks until either an error occurs or
// a Terminal state is encountered.
func (s *defaultScanner) run(ctx context.Context) {
	state, err := stateToStateFunc[s.getState()](s, ctx)
	if err != nil {
		s.handleError(err)
		return
	}

	if state == Terminal {
		log.Printf("got here")
		return
	}

	s.setState(state)
	err = s.Store.SetScanReport(s.report)
	if err != nil {
		s.handleError(err)
		return
	}

	s.run(ctx)
}

// handleError updates the ScanReport to communicate an error and attempts
// to persist this information.
func (s *defaultScanner) handleError(err error) {
	s.logger.Error().Str("state", s.getState().String()).Msg("handling scan error")
	s.report.Success = false
	s.report.Err = err.Error()
	s.report.State = ScanError.String()
	log.Printf("error before set: %v %v", err.Error(), s.report.Err)
	err = s.Store.SetScanReport(s.report)
	if err != nil {
		// just log, we are about to bail anyway
		s.logger.Error().Msgf("failed to push scan report when handling error: %v", err)
	}
}

// setState is a helper method to transition the scanner to the provided next state
func (s *defaultScanner) setState(state ScannerState) {
	s.currentState = state
	s.report.State = state.String()
}

// getState is a concurrency safe method for obtaining the current state of the scanner
func (s *defaultScanner) getState() ScannerState {
	s.sm.RLock()
	ss := s.currentState
	s.sm.RUnlock()
	return ss
}

func (s *defaultScanner) Lock(ctx context.Context, hash string) error {
	err := s.distLock.Lock(ctx, hash)
	if err != nil {
		return err
	}
	return nil
}

func (s *defaultScanner) Unlock() error {
	err := s.distLock.Unlock()
	if err != nil {
		return err
	}
	return nil
}
