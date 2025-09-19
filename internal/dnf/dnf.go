// Package dnf interfaces with dnf 4 and 5 history databases to extract repoid
// information.
//
// This package tries to use "repoid" when referring to a dnf repository's ID,
// to help distinguish it from a [claircore.Repository] ID.
package dnf // import "github.com/quay/claircore/internal/dnf"

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
	"slices"

	"github.com/quay/zlog"
	_ "modernc.org/sqlite" // register the sqlite driver

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpmver"
)

// BUG(hank) The dnf mapping is less useful than it could be because there's no
// reliable way to turn the "repoid" that it reports into something with meaning
// outside of the Red Hat build system's builder's context. See [CLAIRDEV-45]
// for more information.
//
// [CLAIRDEV-45]: https://issues.redhat.com/browse/CLAIRDEV-45

// NOTE(hank) Fedora seems to use some hex identifier for repoids. This might be
// a problem if we ever want to support Fedora.

// PackageSeq is an alias for the Package iterator type.
type PackageSeq = iter.Seq2[claircore.Package, error]

// Wrap closes over the passed [fs.FS] and [PackageSeq] and returns a
// [PackageSeq] that annotates the [claircore.Package]s with the dnf repoid.
func Wrap(ctx context.Context, sys fs.FS, seq PackageSeq) (PackageSeq, error) {
	h, err := openHistoryDB(ctx, sys)
	if err != nil {
		return nil, err
	}

	wrapped := func(yield func(claircore.Package, error) bool) {
		defer h.Close()

		for pkg, err := range seq {
			if err != nil {
				if !yield(pkg, err) {
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
	rows, err := h.db.QueryContext(ctx, h.AllRepoids)
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

const (
	// https://github.com/rpm-software-management/dnf5/blob/5.2.13.0/libdnf5/transaction/db/db.cpp#L78-L89
	pathDnf5 = `usr/lib/sysimage/libdnf5/transaction_history.sqlite`
	// https://github.com/rpm-software-management/libdnf/blob/4.90/libdnf/transaction/Swdb.hpp#L57
	pathDnf4 = `var/lib/dnf/history.sqlite`
)

// HistoryDB is a handle to the dnf history database.
//
// All methods are safe to call on a nil receiver.
type historyDB struct {
	db *sql.DB
	queries
}

// OpenHistoryDB does what it says on the tin.
//
// This function may return a nil *historyDB, which is still safe to use.
func openHistoryDB(ctx context.Context, sys fs.FS) (*historyDB, error) {
	var found string
Stat:
	for _, name := range []string{pathDnf5, pathDnf4} {
		switch _, err := fs.Stat(sys, name); {
		case errors.Is(err, nil):
			found = name
			break Stat
		case errors.Is(err, fs.ErrNotExist): // OK
		default:
			return nil, fmt.Errorf("internal/dnf: unexpected error handling fs.FS: %w", err)
		}
	}
	if found == "" {
		return nil, nil
	}
	var h *historyDB

	f, err := sys.Open(found)
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
	queries, err := pickQueries(ctx, db)
	if err != nil {
		// Error should be annotated already, just return it.
		return nil, err
	}

	h = &historyDB{
		db:      db,
		queries: queries,
	}
	// This is an internal function, so add an extra caller frame.
	_, file, line, _ := runtime.Caller(2)
	runtime.SetFinalizer(h, func(_ *historyDB) {
		panic(fmt.Sprintf("%s:%d: historyDB not closed", file, line))
	})
	return h, nil
}

// PickQueries returns the correct set of queries based on the tables present in
// the database.
func pickQueries(ctx context.Context, db *sql.DB) (q queries, err error) {
	names, err := tableNames(ctx, db)
	if err != nil {
		return q, err
	}
	zlog.Debug(ctx).Strs("tables", names).Msg("found tables in database")

	switch {
	case !slices.Contains(names, `config`):
		q = dnf4Queries
	case !slices.Contains(names, `trans_item_action`):
		q = dnf4Queries
	default:
		q = dnf5Queries
	}

	return q, nil
}

// TableNames reports the tables present in the database.
func tableNames(ctx context.Context, db *sql.DB) (out []string, err error) {
	rows, err := db.QueryContext(ctx, getTables)
	if err != nil {
		return nil, fmt.Errorf("internal/dnf: error querying table names: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("internal/dnf: error reading table name: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("internal/dnf: error reading table names: %w", err)
	}

	slices.Sort(out)
	return out, nil
}

// AddRepoid modifies the passed [claircore.Package] with a discovered dnf
// repoid, if possible.
//
// If any error is reported, the [claircore.Package] value is not modified.
func (h *historyDB) AddRepoid(ctx context.Context, pkg *claircore.Package) error {
	if h == nil {
		return nil
	}

	// TODO(hank) Shouldn't need to build a string like this.
	v := fmt.Sprintf("%s-%s.%s", pkg.Name, pkg.Version, pkg.Arch) // "Version" contains the EVR.
	ver, err := rpmver.Parse(v)
	if err != nil {
		zlog.Warn(ctx).
			Err(err).
			Str("version", v).
			Msg("unable to re-parse rpm version")
		return nil
	}

	var id string
	err = h.db.
		QueryRowContext(ctx, h.RepoidForPackage,
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
	for _, pkg := range []*claircore.Package{pkg, pkg.Source} {
		if pkg == nil {
			continue
		}
		v, err := url.ParseQuery(pkg.RepositoryHint)
		if err != nil {
			return fmt.Errorf("internal/dnf: malformed RepositoryHint (%s: %#q): %w",
				pkg.Name, pkg.RepositoryHint, err)
		}
		v.Add("repoid", id)
		slices.Sort(v["repoid"])
		v["repoid"] = slices.Compact(v["repoid"])
		pkg.RepositoryHint = v.Encode()
	}

	return nil
}

// Close releases held resources.
func (h *historyDB) Close() error {
	if h == nil {
		return nil
	}

	runtime.SetFinalizer(h, nil)
	return h.db.Close()
}
