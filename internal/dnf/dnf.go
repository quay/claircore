// Package dnf interfaces with dnf 4 and 5 history databases to extract repoid
// information.
package dnf

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"net/url"
	"os"
	"runtime"
	"sync"

	"github.com/quay/zlog"
	_ "modernc.org/sqlite" // register the sqlite driver

	"github.com/quay/claircore"
)

// BUG(hank) The dnf mapping is less useful than it could be because there's no
// reliable way to turn the RepoID that it reports into something with meaning
// outside of the Red Hat build system's builder's context. See [CLAIRDEV-45]
// for more information.
//
// [CLAIRDEV-45]: https://issues.redhat.com/browse/CLAIRDEV-45

// BUG(hank) This package needs tests.

// NewAnnotator returns an [Annotator] using any discovered dnf database in the
// provided [fs.FS].
//
// The returned [Annotator] must have its [Close] method called, or the process
// may panic.
//
// If no dnf database is found, the [Identity] [Annotator] will be returned.
func NewAnnotator(ctx context.Context, sys fs.FS) (Annotator, error) {
	toOpen, enum, err := findDatabase(sys)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNoDatabase):
		return Identity, nil
	default:
		return nil, err
	}

	zlog.Debug(ctx).
		Str("path", toOpen).
		Bool("is-5", enum == rmDNF5).
		Msg("found dnf history database")
	r, err := sys.Open(toOpen)
	if err != nil {
		return nil, fmt.Errorf("internal/dnf: unexpected error opening history: %w", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close fs.FS sqlite db file")
		}
	}()

	return newAnnotator(ctx, r, enum)
}

// Annotator produces iterators that map over packages, adding repoid where
// discovered.
type Annotator interface {
	io.Closer
	Wrap(context.Context, iter.Seq[claircore.Package]) (iter.Seq[claircore.Package], func() error)
}

// Identity is an [Annotator] who's [Annotator.Wrap] method does nothing.
//
// Provided as a variable to allow callers to determine if the returned
// [Annotator] will do anything.
//
// [Annotator.Close] is safe to call multiple times.
var Identity Annotator

func init() {
	Identity = ident{}
}

// Ident backs the [Identity] Annotator.
type ident struct{}

// Wrap implements [Annotator].
func (ident) Wrap(_ context.Context, seq iter.Seq[claircore.Package]) (iter.Seq[claircore.Package], func() error) {
	return seq, func() error { return nil }
}

// Close implements [Annotator].
func (ident) Close() error {
	return nil
}

// NewAnnotator holds book-keeping for producing multiple independent mapping
// iterators for a given dnf history database.
func newAnnotator(ctx context.Context, r fs.File, enum int) (*annotator, error) {
	var err error
	a := annotator{
		removedEnum: enum,
	}
	a.db, a.spool, err = openDatabase(ctx, r)
	if err != nil {
		return nil, err
	}

	// Only way to get this is via the outer [NewAnnotator], so skip an extra
	// frame.
	_, file, line, _ := runtime.Caller(2)
	runtime.SetFinalizer(&a, func(_ *annotator) {
		panic(fmt.Sprintf("%s:%d: Annotator not closed", file, line))
	})

	return &a, nil
}

// Annotator holds the state for a mapping iterators that use a given dnf
// database.
type annotator struct {
	spool *os.File
	db    *sql.DB

	// Concurrent maps for memoizing database lookups.
	absent sync.Map
	repo   sync.Map

	// "Removed" action enum.
	removedEnum int
}

// Wrap implements [Annotator].
func (a *annotator) Wrap(ctx context.Context, seq iter.Seq[claircore.Package]) (iter.Seq[claircore.Package], func() error) {
	var final error

	mapFunc := func(yield func(claircore.Package) bool) {
		for pkg := range seq {
			key := rpm.NERVA(&pkg)
			// If a previous iteration found that a Name is definitely not
			// present, do nothing:
			if _, ok := a.absent.Load(key); ok {
				if !yield(pkg) {
					return
				}
				continue
			}

			// If this is an unknown Package, look up the repoid.
			// Otherwise, use the known repoid.
			var id string
			if idAny, ok := a.repo.Load(key); !ok {
				err := a.db.
					QueryRowContext(ctx, repoidForPackage, a.removedEnum, key).
					Scan(&id)
				switch {
				case errors.Is(err, nil):
					a.repo.Store(key, id)
				case errors.Is(err, sql.ErrNoRows):
					a.absent.Store(key, struct{}{})
					if !yield(pkg) {
						return
					}
					continue
				default:
					final = fmt.Errorf("internal/dnf: database error: %w", err)
					return
				}
			} else {
				id = idAny.(string)
			}
			// Re-parse and edit the RepositoryHint.
			//
			// It's annoying to do this, a [claircore.Package] redesign should
			// make sure to fix this wart where we need structured information
			// in a string.
			v, err := url.ParseQuery(pkg.RepositoryHint)
			if err != nil {
				final = fmt.Errorf("internal/dnf: malformed RepositoryHint (%s: %#q): %w",
					pkg.Name, pkg.RepositoryHint, err)
				return
			}
			v.Add("repoid", id)
			pkg.RepositoryHint = v.Encode()

			if !yield(pkg) {
				return
			}

		}
	}

	return mapFunc, func() error { return final }
}

// Close implements [Annotator].
func (a *annotator) Close() error {
	runtime.SetFinalizer(a, nil)
	return errors.Join(a.db.Close(), os.Remove(a.spool.Name()))
}

// FindRepoids reports all the repoids discovered in the dnf history database in
// the provided [fs.FS].
func FindRepoids(ctx context.Context, sys fs.FS) ([]string, error) {
	toOpen, enum, err := findDatabase(sys)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNoDatabase):
		return nil, nil
	default:
		return nil, err
	}

	r, err := sys.Open(toOpen)
	if err != nil {
		return nil, fmt.Errorf("internal/dnf: unexpected error opening history: %w", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close fs.FS sqlite db file")
		}
	}()
	db, spool, err := openDatabase(ctx, r)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := db.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db")
		}
		if err := os.Remove(spool.Name()); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to remove spool file")
		}
	}()

	var ret []string
	rows, err := db.QueryContext(ctx, allRepoids, enum)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("error closing returned rows")
		}
	}()

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("internal/dnf: error scanning repoid: %w", err)
		}
		ret = append(ret, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("internal/dnf: error reading rows: %w", err)
	}

	return ret, nil
}

func findDatabase(sys fs.FS) (toOpen string, rm int, err error) {
	for i, p := range []string{
		`usr/lib/sysimage/libdnf5/transaction_history.sqlite`, // dnf5 location
		`var/lib/dnf/history.sqlite`,                          // dnf3/4 location
	} {
		switch _, err := fs.Stat(sys, p); {
		case errors.Is(err, nil):
			return p, removedEnum(i == 0), nil
		case errors.Is(err, fs.ErrNotExist): // OK
		default:
			return "", 0, fmt.Errorf("internal/dnf: unexpected error handling fs.FS: %w", err)
		}
	}
	return "", 0, errNoDatabase
}

var errNoDatabase = errors.New("no database found")

// RemovedEnum reports the enum for a "removed" action for the indicated
// database version.
func removedEnum(is5 bool) int {
	// Defined here:
	// https://github.com/rpm-software-management/dnf5/blob/13886935418e28482de7b675169482b85303845d/include/libdnf/transaction/transaction_item_action.hpp#L35
	if is5 {
		return rmDNF5
	}
	// Defined here:
	// https://github.com/rpm-software-management/libdnf/blob/93759bc5cac262906e52b6a173d7b157914ec29e/libdnf/transaction/Types.hpp#L45
	return rmDNF4
}

const (
	rmDNF5 = 5
	rmDNF4 = 8
)

// OpenDatabase contains all the logic for opening the provided [fs.File] as a
// [sql.DB].
//
// The returned [os.File] is already closed.
func openDatabase(ctx context.Context, r fs.File) (*sql.DB, *os.File, error) {
	// Currently needs to be linked into the filesystem.
	// See also: quay/claircore#720
	f, err := os.CreateTemp(os.TempDir(), `dnf.sqlite.*`)
	if err != nil {
		return nil, nil, fmt.Errorf("internal/dnf: error reading sqlite db: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db file")
		}
	}()

	zlog.Debug(ctx).Str("file", f.Name()).Msg("copying sqlite db out of tar")
	if _, err := io.Copy(f, r); err != nil {
		return nil, nil, fmt.Errorf("internal/dnf: error spooling sqlite db: %w", errors.Join(err, os.Remove(f.Name())))
	}
	if err := f.Sync(); err != nil {
		return nil, nil, fmt.Errorf("internal/dnf: error spooling sqlite db: %w", errors.Join(err, os.Remove(f.Name())))
	}

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("internal/dnf: error reading sqlite db: %w", errors.Join(err, os.Remove(f.Name())))
	}
	return db, f, nil
}
