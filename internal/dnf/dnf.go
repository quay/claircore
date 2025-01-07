// Package dnf interfaces with dnf 4 and 5 history databases to extract repoid
// information.
//
// This package tries to use "repoid" when referring to a dnf repository's ID,
// to help distinguish it from a [claircore.Repository] ID.
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

	"github.com/quay/zlog"
	_ "modernc.org/sqlite" // register the sqlite driver

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

// BUG(hank) The dnf mapping is less useful than it could be because there's no
// reliable way to turn the RepoID that it reports into something with meaning
// outside of the Red Hat build system's builder's context. See [CLAIRDEV-45]
// for more information.
//
// [CLAIRDEV-45]: https://issues.redhat.com/browse/CLAIRDEV-45

type PackageSeq = iter.Seq2[claircore.Package, error]

func Wrap(ctx context.Context, sys fs.FS, seq PackageSeq) (PackageSeq, error) {
	h, err := openHistoryDB(ctx, sys)
	if err != nil {
		return nil, err
	}

	wrapped := func(yield func(claircore.Package, error) bool) {
		defer h.Close()

		for pkg, err := range seq {
			if err != nil {
				if !yield(claircore.Package{}, err) {
					return
				}
				continue
			}

			err = h.AddRepoid(ctx, &pkg)
			if !yield(pkg, err) {
				return
			}
		}
	}
	return wrapped, nil
}

// FindRepoids reports all the repoids discovered in the dnf history database in
// the provided [fs.FS].
func FindRepoids(ctx context.Context, sys fs.FS) ([]string, error) {
	h, err := openHistoryDB(ctx, sys)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, nil
	}
	defer h.Close()

	var ret []string
	rows, err := h.db.QueryContext(ctx, allRepoids, h.rm)
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

type dbVer struct {
	Path string
	Enum int
}

var possible = []dbVer{
	// Defined here:
	// https://github.com/rpm-software-management/dnf5/blob/13886935418e28482de7b675169482b85303845d/include/libdnf/transaction/transaction_item_action.hpp#L35
	{Path: `usr/lib/sysimage/libdnf5/transaction_history.sqlite`, Enum: 5}, // dnf5
	// Defined here:
	// https://github.com/rpm-software-management/libdnf/blob/93759bc5cac262906e52b6a173d7b157914ec29e/libdnf/transaction/Types.hpp#L45
	{Path: `var/lib/dnf/history.sqlite`, Enum: 8}, // dnf3/4
}

// HistoryDB ...
//
// All methods are safe to call on a nil receiver.
type historyDB struct {
	db *sql.DB
	rm int
}

func openHistoryDB(ctx context.Context, sys fs.FS) (*historyDB, error) {
	var found *dbVer
	for _, v := range possible {
		switch _, err := fs.Stat(sys, v.Path); {
		case errors.Is(err, nil):
			found = &v
		case errors.Is(err, fs.ErrNotExist): // OK
		default:
			return nil, fmt.Errorf("internal/dnf: unexpected error handling fs.FS: %w", err)
		}
	}
	if found == nil {
		return nil, nil
	}
	var h *historyDB

	f, err := sys.Open(found.Path)
	if err != nil {
		return nil, fmt.Errorf("internal/dnf: unexpected error opening history: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close fs.FS db file")
		}
	}()

	// Needs to be linked into the filesystem for the sqlite driver to open it.
	// See also: quay/claircore#720
	spool, err := os.CreateTemp(os.TempDir(), `dnf.sqlite.*`)
	if err != nil {
		return nil, fmt.Errorf("internal/dnf: error reading sqlite db: %w", err)
	}
	defer func() {
		if err := spool.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db file")
		}
		// If in an error return, make sure to clean up the spool file.
		if h == nil {
			if err := os.Remove(spool.Name()); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to unlink sqlite db file")
			}
		}
	}()

	zlog.Debug(ctx).Str("file", spool.Name()).Msg("copying sqlite db out of tar")
	if _, err := io.Copy(spool, f); err != nil {
		return nil, fmt.Errorf("internal/dnf: error spooling sqlite db: %w", err)
	}
	if err := spool.Sync(); err != nil {
		return nil, fmt.Errorf("internal/dnf: error spooling sqlite db: %w", err)
	}

	db, err := sql.Open("sqlite", spool.Name())
	if err != nil {
		return nil, fmt.Errorf("internal/dnf: error reading sqlite db: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("internal/dnf: error reading sqlite db: %w", err)
	}

	h = &historyDB{
		db: db,
		rm: found.Enum,
	}
	runtime.AddCleanup(db, func(p string) {
		os.Remove(p)
	}, spool.Name())
	// This is an internal function, so add an extra caller frame.
	_, file, line, _ := runtime.Caller(2)
	runtime.SetFinalizer(h, func(_ *historyDB) {
		panic(fmt.Sprintf("%s:%d: historyDB not closed", file, line))
	})
	return h, nil
}

// AddRepoid ...
//
// If any error is reported, the [claircore.Package] value is not modified.
func (h *historyDB) AddRepoid(ctx context.Context, pkg *claircore.Package) error {
	if h == nil {
		return nil
	}

	// TODO(hank) Shouldn't need to build a string like this.
	ver, err := rpmver.Parse(fmt.Sprintf("%s-%s.%s", pkg.Name, pkg.Version, pkg.Arch))
	if err != nil {
		// TODO(hank) Log?
		return nil
	}

	var id string
	err = h.db.
		QueryRowContext(ctx, repoidForPackage, h.rm,
			*ver.Name, ver.Epoch, ver.Version, ver.Release, *ver.Architecture).
		Scan(&id)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return nil
	default:
		return fmt.Errorf("internal/dnf: database error: %w", err)
	}

	// Re-parse and edit the RepositoryHint.
	//
	// It's annoying to do this, a [claircore.Package] redesign should make sure
	// to fix this wart where we need structured information in a string.
	v, err := url.ParseQuery(pkg.RepositoryHint)
	if err != nil {
		return fmt.Errorf("internal/dnf: malformed RepositoryHint (%s: %#q): %w",
			pkg.Name, pkg.RepositoryHint, err)
	}
	v.Add("repoid", id)
	pkg.RepositoryHint = v.Encode()

	return nil
}

func (h *historyDB) Close() error {
	if h == nil {
		return nil
	}

	runtime.SetFinalizer(h, nil)
	return h.db.Close()
}
