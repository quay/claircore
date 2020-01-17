package updater

import (
	"context"
	"fmt"
	"io"
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

	// fetch and check if we need to update.
	vulnDB, shouldUpdate, updateHash, err := u.fetchAndCheck(ctx)
	if err != nil {
		return err
	}
	if !shouldUpdate {
		log.Debug().Msg("no updates necessary")
		return nil
	}
	defer vulnDB.Close()

	// parse the vulnDB and put the parsed contents into the vulnstore
	err = u.parseAndStore(ctx, vulnDB, updateHash)
	if err != nil {
		return err
	}

	log.Info().Msg("successfully updated the vulnstore")
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

// fetchAndCheck calls the Fetch method on the embedded Updater interface and checks whether we should update
func (u *Controller) fetchAndCheck(ctx context.Context) (io.ReadCloser, bool, driver.Fingerprint, error) {
	// retrieve vulnerability database
	vulnDB, updateHash, err := u.Fetch(ctx, "")
	if err != nil {
		return nil, false, "", fmt.Errorf("failed to fetch database: %v", err)
	}

	// see if we need to update the vulnstore
	prevUpdateHash, err := u.Store.GetHash(ctx, u.Name)
	if err != nil {
		vulnDB.Close()
		return nil, false, "", fmt.Errorf("failed to get previous update hash: %v", err)
	}
	if driver.Fingerprint(prevUpdateHash) == updateHash {
		vulnDB.Close()
		return nil, false, "", nil
	}

	return vulnDB, true, updateHash, nil
}

// parseAndStore calls the parse method on the embedded Updater interface and stores the result
func (u *Controller) parseAndStore(ctx context.Context, vulnDB io.ReadCloser, updateHash driver.Fingerprint) error {
	// parse the vulnDB into claircore.Vulnerability structs
	vulns, err := u.Parse(ctx, vulnDB)
	if err != nil {
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	// store the vulnerabilities and update latest hash
	err = u.Store.PutVulnerabilities(ctx, u.Name, string(updateHash), vulns)
	if err != nil {
		return fmt.Errorf("failed to store vulernabilities: %v", err)
	}

	return nil
}
