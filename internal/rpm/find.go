// Package rpm provides the ability to inspect rpm databases.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
	"github.com/quay/claircore/internal/rpm/sqlite"
)

// FindDBs walks the passed [fs.FS] looking for any files that seem to be rpm
// databases.
//
// The returned [FoundDB] instances close over the passed [fs.FS]
func FindDBs(ctx context.Context, sys fs.FS) ([]FoundDB, error) {
	found := make([]FoundDB, 0)
	if err := fs.WalkDir(sys, ".", walk(ctx, &found, sys)); err != nil {
		return nil, fmt.Errorf("internal/rpm: error walking fs: %w", err)
	}
	slices.SortFunc(found, func(a, b FoundDB) int {
		cmp := strings.Compare(a.path, b.path)
		if cmp == 0 {
			switch {
			case a.kind < b.kind:
				cmp = -1
			case a.kind > b.kind:
				cmp = +1
			}
		}
		return cmp
	})
	found = slices.CompactFunc(found, func(a, b FoundDB) bool {
		return a.path == b.path
	})
	return found, nil
}

// Walk is a WalkDirFunc to find rpm databases.
func walk(ctx context.Context, out *[]FoundDB, sys fs.FS) fs.WalkDirFunc {
	type checkFunc func(context.Context, io.Reader) bool
	testpath := func(name string, fn checkFunc) (bool, error) {
		f, err := sys.Open(name)
		if err != nil {
			return false, err
		}
		ok := fn(ctx, f)
		return ok, f.Close()
	}

	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		dir, n := path.Split(p)
		dir = path.Clean(dir)
		db := FoundDB{
			sys:  sys,
			path: dir,
		}
		switch n {
		case `Packages`:
			db.kind = kindBDB
			if ok, err := testpath(p, bdb.CheckMagic); !ok {
				return err
			}
		case `rpmdb.sqlite`:
			db.kind = kindSQLite
		case `Packages.db`:
			db.kind = kindNDB
			if ok, err := testpath(p, ndb.CheckMagic); !ok {
				return err
			}
		}
		if db.kind != 0 {
			*out = append(*out, db)
		}
		return nil
	}
}

// FoundDB represents an rpm database discovered in an [fs.FS].
//
// Instances close over the [fs.FS] that was used to create it.
type FoundDB struct {
	sys  fs.FS
	path string
	kind dbKind
}

// String implements [fmt.Stringer].
func (db FoundDB) String() string {
	return db.kind.String() + ":" + db.path
}

// Open does any necessary setup and returns the uniform [NativeDB] interface.
func (db FoundDB) Open(ctx context.Context) (NativeDB, error) {
	db.kind.validate()
	var inner innerDB

	f, err := db.sys.Open(path.Join(db.path, db.kind.filename()))
	if err != nil {
		return nil, fmt.Errorf("internal/rpm: error reading %s db: %w", db.kind.String(), err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Stringer("kind", db.kind).Err(err).Msg("unable to close db")
		}
	}()
	spool, cleanup, err := db.createSpool(ctx, f)
	if err != nil {
		return nil, err
	}

	switch db.kind {
	case kindSQLite:
		n, ok := spool.(interface {
			Name() string
		})
		if !ok {
			return nil, errors.New("internal/rpm: error reading sqlite db: unable to determine spoolfile name")
		}
		sdb, err := sqlite.Open(n.Name())
		if err != nil {
			return nil, fmt.Errorf("internal/rpm: error reading sqlite db: %w", err)
		}
		inner = sdb
	case kindBDB:
		var bpdb bdb.PackageDB
		if err := bpdb.Parse(spool); err != nil {
			return nil, fmt.Errorf("internal/rpm: error parsing bdb db: %w", err)
		}
		inner = &bpdb
	case kindNDB:
		var npdb ndb.PackageDB
		if err := npdb.Parse(spool); err != nil {
			return nil, fmt.Errorf("internal/rpm: error parsing ndb db: %w", err)
		}
		inner = &npdb
	default:
		panic("unreachable")
	}
	zlog.Debug(ctx).
		Stringer("db", db).
		Msg("opened database")

	if err := inner.Validate(ctx); err != nil {
		if cleanup != nil {
			err = errors.Join(err, cleanup())
		}
		if closer, ok := inner.(io.Closer); ok {
			err = errors.Join(err, closer.Close())
		}
		return nil, err
	}

	return &nativeAdapter{
		innerDB: inner,
		cleanup: cleanup,
	}, nil
}

// Packages opens the package database and returns an iterator over the
// packages.
func (db FoundDB) Packages(ctx context.Context) (iter.Seq[claircore.Package], func() error) {
	nat, err := db.Open(ctx)
	if err != nil {
		return fused, func() error { return err }
	}
	return PackagesFromDB(ctx, db.kind.String(), nat)
}

// Fused is an iterator that returns no values.
func fused(_ func(claircore.Package) bool) {}

// CreateSpool creates a spool file.
func (db FoundDB) createSpool(ctx context.Context, f fs.File) (io.ReaderAt, func() error, error) {
	if r, ok := f.(io.ReaderAt); ok {
		return r, func() error { return nil }, nil
	}
	spool, err := os.CreateTemp(os.TempDir(), `Packages.`+db.kind.String()+`.`)
	if err != nil {
		return nil, nil, fmt.Errorf("rpm: error spooling db: %w", err)
	}
	ctx = zlog.ContextWithValues(ctx, "file", spool.Name())
	zlog.Debug(ctx).
		Msg("copying db out of fs.FS")

	// Need to have the file linked into the filesystem for the sqlite package.
	//
	// See [this post] for an idea on working around it:
	//
	//	int sqlite_fdopen(
	//		int fd,
	//		sqlite3 **connection)
	//	{
	//		char uri[48];
	//
	//		snprintf(uri, sizeof uri, "file:///dev/fd/%d?immutable=1", fd);
	//		return sqlite3_open_v2(
	//			uri,
	//			connection,
	//			SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
	//			NULL);
	//	}
	//
	// [this post]: https://sqlite.org/forum/info/57aaaf20cf703d301fed5aeaef59e70723f1d9454fb3a4e6383b2bfac6897e5a
	cleanup := func() error {
		return errors.Join(
			spool.Close(),
			os.Remove(spool.Name()),
		)
	}

	if err := errors.Join(
		func() error { _, err := io.Copy(spool, f); return err }(),
		spool.Sync(),
	); err != nil {
		if err := cleanup(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close spool")
		}
		return nil, nil, fmt.Errorf("rpm: error spooling db: %w", err)
	}

	return spool, cleanup, nil
}

// DbKind is an enum of known rpm database backends.
type dbKind uint

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -linecomment -type dbKind

const (
	_ dbKind = iota

	kindBDB    // bdb
	kindSQLite // sqlite
	kindNDB    // ndb
)

func (k dbKind) filename() string {
	switch k {
	case kindBDB:
		return `Packages`
	case kindSQLite:
		return `rpmdb.sqlite`
	case kindNDB:
		return `Packages.db`
	}
	panic("programmer error: bad kind: " + k.String())
}

func (k dbKind) validate() {
	if k < kindBDB || k > kindNDB {
		panic("programmer error: bad kind: " + k.String())
	}
}
