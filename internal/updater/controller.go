package updater

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// Controller is the interface that updater Controllers implement.
type Controller interface {
	// Run has the Controller execute all the Updaters passed on the channel,
	// until it's closed. The method runs synchronously and only returns after
	// the channel is closed or the context is canceled.
	//
	// Any spawned goroutines should inherit the passed-in Context.
	//
	// A call to Run should be thought of as one execution of the Updaters.
	// If a caller wants to call Run in a loop, it should use a new channel on
	// each iteration.
	Run(context.Context, <-chan driver.Updater) error
}

// Errmap is a wrapper around a group of errors.
type errmap struct {
	sync.Mutex
	m map[string]error
}

func (e *errmap) add(name string, err error) {
	e.Lock()
	defer e.Unlock()
	e.m[name] = err
}

func (e *errmap) len() int {
	e.Lock()
	defer e.Unlock()
	return len(e.m)
}

func (e *errmap) error() error {
	e.Lock()
	defer e.Unlock()
	var b strings.Builder
	b.WriteString("updating errors:\n")
	for n, err := range e.m {
		fmt.Fprintf(&b, "\t%s: %v\n", n, err)
	}
	return errors.New(b.String())
}

// DriveUpdater drives the updater.
//
// The caller is expected to handle any locking or concurrency control needed.
func driveUpdater(ctx context.Context, log zerolog.Logger, u driver.Updater, s vulnstore.Updater) error {
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	name := u.Name()

	var prevFP driver.Fingerprint
	// Get previous fingerprint, if present.
	// A fingerprint being missing is not an error.
	opmap, err := s.GetUpdateOperations(ctx, name)
	if err != nil {
		return err
	}
	if s := opmap[name]; len(s) > 0 {
		prevFP = s[0].Fingerprint
	}

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

	vulns, err := u.Parse(ctx, vulnDB)
	if err != nil {
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	ref, err := s.UpdateVulnerabilities(ctx, name, newFP, vulns)
	if err != nil {
		return fmt.Errorf("failed to update vulnerabilities: %v", err)
	}

	log.Info().
		Str("ref", ref.String()).
		Msg("successful update")
	return nil
}
