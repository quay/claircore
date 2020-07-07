package postgres

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
)

// Lock implements the distlock.Locker interface. Locker utilizes
// postgres transaction advisor locks to implement a distributed lock.
type lock struct {
	// a database instance where we can create pg_advisory locks
	db *sqlx.DB
	// the frequency we would like to attempt a lock acquistion
	retry time.Duration
	// mu ensures TryLock() and UnLock() have exclusive access to the locked bool.
	mu sync.Mutex
	// whether a lock has been acquired or not
	locked bool
	// the key used to identify this unique lock
	key string
	// the transcation in which the lock is beind held. commiting this
	// transaction will release the advisory lock
	tx *sqlx.Tx
}

func NewLock(db *sqlx.DB, retry time.Duration) *lock {
	return &lock{
		db:    db,
		retry: retry,
	}
}

// Lock will immediately attempt to obtain a lock with the key
// being the provided hash. on failure of initial attempt a new attempt
// will be made every l.retry interval. Once lock is acquired the
// method unblocks
func (l *lock) Lock(ctx context.Context, key string) error {
	if l.locked {
		return fmt.Errorf("attempt to lock while lock held")
	}

	// attempt initial lock acquisition. we throw away the bool and prefer
	// checking l.locked bool which l.TryLock flips under mu lock
	_, err := l.TryLock(ctx, key)
	if err != nil {
		return fmt.Errorf("failed at attmpeting initial lock acquition: %v", err)
	}
	if l.locked {
		return nil
	}

	// if initial attempt failed begin retry loop.
	t := time.NewTicker(l.retry)
	defer t.Stop()

	for !l.locked {
		select {
		case <-t.C:
			_, err := l.TryLock(ctx, key)
			if err != nil {
				return fmt.Errorf("failed at attmpeting initial lock acquition: %v", err)
			}
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %v", ctx.Err())
		}
	}

	return nil
}

// UnLock first checks if the scanLock is in a locked state, secondly checks to
// confirm the tx field is not nil, and lastly will commit the tx allowing
// other calls to Lock() to succeed and sets l.locked = false.
func (l *lock) Unlock() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.locked {
		return fmt.Errorf("attempted to unlock when no lock has been acquired")
	}
	if l.tx == nil {
		return fmt.Errorf("attempted to unlock but no transaction is populdated in scanLock")
	}

	// commiting the transaction will free the pg_advisory lock allowing other
	// instances utilizing a lock to proceed
	err := l.tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction and free lock: %v", err)
	}
	l.locked = false

	return nil
}

// TryLock will begin a transaction and then attempt to acquire a pg_advisory transaction
// lock. On success it will set sl.locked = true and populate sl.tx with the transaction
// holding the lock. on any errors we rollback the transcation (unlocking any other scanLocks)
// and return the error. if this process dies a TCP reset will be sent to postgres and the transaction
// will be closed allowing other scanLocks to acquire.
func (l *lock) TryLock(ctx context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.locked {
		return false, nil
	}

	keyInt64 := crushkey(key)

	// start transaction
	tx, err := l.db.Beginx()
	if err != nil {
		return false, err
	}

	// attempt to acquire lock
	var acquired bool

	err = tx.Get(&acquired, manifestAdvisoryLock, keyInt64)
	if err != nil {
		tx.Rollback()
		return false, fmt.Errorf("failed to issue pg_advisory lock query: %v", err)
	}

	// if acquired set lock status which unblocks caller waiting on Lock() method
	// and populate tx which will be Commited on Unlock()
	if acquired {
		l.locked = true
		// hold this tx until Unlock() is called!
		l.tx = tx
		return true, nil
	}

	// we did not acquire the lock
	tx.Rollback()
	return false, nil
}
