package updater

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/distlock"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Controller is a control structure for fetching, parsing, and updating a vulnstore.
type Controller struct {
	*Opts
	// a logger with context
	logger zerolog.Logger
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
	logger := log.With().Str("component", "update-controller").Str("name", opts.Name).Str("interval", opts.Interval.String()).Logger()
	return &Controller{
		Opts:   opts,
		logger: logger,
	}
}

// Start begins a long running update controller. cancel ctx to stop.
func (u *Controller) Start(ctx context.Context) error {
	u.logger.Info().Msg("now running")
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
	u.logger.Info().Msgf("looking for updates")
	// attempt to get distributed lock. if we cannot another updater is currently updating the vulnstore
	locked, err := u.tryLock(ctx)
	if err != nil {
		u.logger.Error().Msgf("unexpected error while trying lock: %v", err)
		return err
	}
	if !locked {
		u.logger.Debug().Msgf("another process is updating. waiting till next update interval")
		return nil
	}
	defer u.Lock.Unlock()

	// fetch and check if we need to update.
	vulnDB, shouldUpdate, updateHash, err := u.fetchAndCheck(ctx)
	if err != nil {
		u.logger.Error().Msgf("%v. lock released", err)
		return err
	}
	if !shouldUpdate {
		u.logger.Info().Msgf("no updates were necessary. lock released")
		return nil
	}
	defer vulnDB.Close()

	// parse the vulnDB and put the parsed contents into the vulnstore
	err = u.parseAndStore(ctx, vulnDB, updateHash)
	if err != nil {
		u.logger.Error().Msgf("%v", err)
		return err
	}

	u.logger.Info().Msg("successfully updated the vulnstore")
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
func (u *Controller) fetchAndCheck(ctx context.Context) (io.ReadCloser, bool, string, error) {
	// retrieve vulnerability database
	vulnDB, updateHash, err := u.Fetch()
	if err != nil {
		return nil, false, "", fmt.Errorf("failed to fetch database: %v", err)
	}

	// see if we need to update the vulnstore
	prevUpdateHash, err := u.Store.GetHash(ctx, u.Name)
	if err != nil {
		vulnDB.Close()
		return nil, false, "", fmt.Errorf("failed to get previous update hash: %v", err)
	}
	if prevUpdateHash == updateHash {
		vulnDB.Close()
		return nil, false, "", nil
	}

	return vulnDB, true, updateHash, nil
}

// parseAndStore calls the parse method on the embedded Updater interface and stores the result
func (u *Controller) parseAndStore(ctx context.Context, vulnDB io.ReadCloser, updateHash string) error {
	// parse the vulnDB into claircore.Vulnerability structs
	vulns, err := u.Parse(vulnDB)
	if err != nil {
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	// store the vulnerabilities and update latest hash
	err = u.Store.PutVulnerabilities(ctx, u.Name, updateHash, vulns)
	if err != nil {
		return fmt.Errorf("failed to store vulernabilities: %v", err)
	}

	return nil
}
