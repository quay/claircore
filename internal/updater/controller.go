package updater

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/distlock"
)

// Controller is a control structure for fetching, parsing, and updating a vulnstore.
type Controller struct {
	*Opts
}

// Opts are options used to create an Updater
type Opts struct {
	// an embedded updater interface
	driver.Updater
	// a unique name for this controller. must be unique between controllers
	Name string
	// store for persistence
	Store vulnstore.Updater
	// update interval
	Interval time.Duration
	// lock to ensure only process updating
	Lock distlock.Locker
	// immediately update on construction
	UpdateOnStart bool
}

// New is a constructor for an Controller
func New(opts *Opts) *Controller {
	return &Controller{
		Opts: opts,
	}
}

// Start begins a long running update controller. cancel ctx to stop.
func (u *Controller) Start(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/updater/Controller").
		Str("name", u.Name).
		Dur("interval", u.Interval).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("controller running")
	go u.start(ctx)
	return nil
}

// start implements the event loop of an updater controller
func (u *Controller) start(ctx context.Context) {
	t := time.NewTicker(u.Interval)
	defer t.Stop()

	if u.UpdateOnStart {
		u.Update(ctx)
	}

	for {
		select {
		case <-t.C:
			u.Update(ctx)
		case <-ctx.Done():
			log.Printf("updater %v is exiting due to context cancelation: %v", u.Name, ctx.Err())
			return
		}
	}
}

// Update triggers an update procedure. exported to make testing easier.
func (u *Controller) Update(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/updater/Controller.Update").
		Str("updater", u.Updater.Name()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("looking for updates")
	// attempt to get distributed lock. if we cannot another updater is currently updating the vulnstore
	locked, err := u.tryLock(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Msg("unexpected error while trying lock")
		return err
	}
	if !locked {
		log.Debug().Msg("another process is updating. waiting till next update interval")
		return nil
	}
	defer u.Lock.Unlock()

	// retrieve previous fingerprint. GetUpdateOperations will
	// return update operations in descending order
	var prevFP driver.Fingerprint
	allUOs, err := u.Store.GetUpdateOperations(ctx, u.Updater.Name())
	if err != nil {
		return err
	}
	UOs := allUOs[u.Updater.Name()]
	if len(UOs) > 0 {
		prevFP = UOs[0].Fingerprint
	}

	// Fetch the vulnerability database. if the fetcher
	// determines no update is necessary a driver.Unchanged
	// error will be returned
	vulnDB, newFP, err := u.Fetch(ctx, prevFP)
	if vulnDB != nil {
		defer vulnDB.Close()
	}
	switch {
	case err == nil:
	case errors.Is(err, driver.Unchanged):
		log.Info().Msg("vulnerability database unchanged")
		return nil
	default:
		return err
	}

	// parse the vulndb
	vulns, err := u.Parse(ctx, vulnDB)
	if err != nil {
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	// update the vulnstore
	ref, err := u.Store.UpdateVulnerabilities(ctx, u.Updater.Name(), newFP, vulns)
	if err != nil {
		return fmt.Errorf("failed to update vulnerabilities: %v", err)
	}

	log.Info().
		Str("ref", ref.String()).
		Msg("successfully updated the vulnstore")
	return nil
}

// lock attempts to acquire a distributed lock
func (u *Controller) tryLock(ctx context.Context) (bool, error) {
	// attempt lock acquisiton
	ok, err := u.Lock.TryLock(ctx, u.Name)
	if err != nil {
		return false, fmt.Errorf("experienced an unexpected error when acquiring lock %v", err)
	}
	// did not acquire, another process is updating the database. bail
	return ok, err
}
