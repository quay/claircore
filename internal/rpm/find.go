package rpm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"path"

	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
	"github.com/quay/claircore/internal/rpm/sqlite"
)

// FindDBs walks the passed [fs.FS] looking for any files that seem to be rpm
// databases.
//
// The returned iterator closes over the passed [fs.FS]. The returned [FoundDB]
// values are only valid to use with the same [fs.FS] value.
func FindDBs(ctx context.Context, sys fs.FS) (iter.Seq[FoundDB], func() error) {
	iterationDone := errors.New("iteration done")
	ctx, done := context.WithCancelCause(ctx)
	// Errgroup not really necessary -- this could be done with a shared
	// variable and a channel -- but the API is nice.
	eg, ctx := errgroup.WithContext(ctx)

	ch := make(chan FoundDB)
	eg.Go(func() error {
		defer close(ch)
		return fs.WalkDir(sys, ".", walk(ctx, ch, sys))
	})
	seq := func(yield func(FoundDB) bool) {
		defer done(iterationDone)
		for {
			select {
			case f, ok := <-ch:
				if !ok {
					return
				}
				if !yield(f) {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
	errFunc := func() error {
		done(iterationDone)
		err := eg.Wait()
		// If the iterator exhausted normally or this function was called early,
		// ignore the cancellation.
		if errors.Is(err, context.Canceled) &&
			errors.Is(context.Cause(ctx), iterationDone) {
			err = nil
		}
		return err
	}

	return seq, errFunc
}

func walk(ctx context.Context, out chan<- FoundDB, sys fs.FS) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		dir, n := path.Split(p)
		dir = path.Clean(dir)
		var kind dbKind
		switch n {
		case `Packages`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			ok := bdb.CheckMagic(ctx, f)
			f.Close()
			if !ok {
				return nil
			}
			kind = kindBDB
		case `rpmdb.sqlite`:
			kind = kindSQLite
		case `Packages.db`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			ok := ndb.CheckMagic(ctx, f)
			f.Close()
			if !ok {
				return nil
			}
			kind = kindNDB
		}
		if kind == 0 {
			return nil
		}

		select {
		case out <- FoundDB{
			path: dir,
			kind: kind,
		}:
			// OK
		case <-ctx.Done():
			return fs.SkipAll
		}
		return nil
	}
}

// FoundDB is a pointer to a probable rpm database found in an [fs.FS].
type FoundDB struct {
	path string
	kind dbKind
}

// String implements [fmt.Stringer].
func (f FoundDB) String() string {
	return f.kind.String() + ":" + f.path
}

// Filename constructs the path to the main database file.
func (f FoundDB) filename() string {
	var n string
	switch f.kind {
	case kindBDB:
		n = `Packages`
	case kindSQLite:
		n = `rpmdb.sqlite`
	case kindNDB:
		n = `Packages.db`
	default:
		panic("programmer error: bad kind: " + f.kind.String())
	}
	return path.Join(f.path, n)
}

// OpenDB attempts to open the database pointed to by "found."
func OpenDB(ctx context.Context, sys fs.FS, found FoundDB) (*Database, error) {
	// Previous incarnations of this package ended up duplicating large chunks
	// of logic around opening the databases. This pass attempts to fix that by
	// using new go features.

	if found.kind == 0 {
		return nil, errors.New("internal/rpm: programmer error: passed zero FoundDB")
	}
	// TODO(hank) Cook up some test against passing the wrong [fs.FS]. Don't use
	// the unique package.

	cleanup := &databaseCleanup{}
	db := Database{
		pkgdb:   found.String(),
		cleanup: cleanup,
	}

	switch found.kind {
	case kindSQLite:
		sdb, err := sqlite.OpenFS(sys, found.filename())
		if err != nil {
			return nil, fmt.Errorf("internal/rpm: unable to open sqlite db: %w", err)
		}
		db.headers = sdb
		cleanup.close = sdb.Close
	case kindBDB, kindNDB:
		r, err := db.openOrBuffer(ctx, sys, found)
		if err != nil {
			return nil, fmt.Errorf("internal/rpm: unable to open %s db: %w", found.kind.String(), err)
		}
		switch found.kind {
		case kindBDB:
			var bpdb bdb.PackageDB
			if err := bpdb.Parse(r); err != nil {
				return nil, fmt.Errorf("internal/rpm: error parsing bdb db: %w", err)
			}
			db.headers = &bpdb
		case kindNDB:
			var npdb ndb.PackageDB
			if err := npdb.Parse(r); err != nil {
				return nil, fmt.Errorf("internal/rpm: error parsing ndb db: %w", err)
			}
			db.headers = &npdb
		default:
			panic("unreachable")
		}
	default:
		panic("unreachable")
	}
	slog.DebugContext(ctx, "opened database", "db", found)

	if v, ok := db.headers.(validator); ok {
		if err := v.Validate(ctx); err != nil {
			return nil, errors.Join(err, db.Close())
		}
	}

	return &db, nil
}

func (db *Database) openOrBuffer(_ context.Context, sys fs.FS, found FoundDB) (io.ReaderAt, error) {
	f, err := sys.Open(found.filename())
	if err != nil {
		return nil, err
	}
	r, ok := f.(io.ReaderAt)
	if ok {
		db.cleanup = f
		return r, nil
	}
	defer f.Close()

	var buf bytes.Buffer
	if fi, err := f.Stat(); err == nil {
		buf.Grow(int(fi.Size()))
	}
	if _, err := io.Copy(&buf, f); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

type databaseCleanup struct {
	spool *os.File
	close func() error
}

func (c *databaseCleanup) Close() (err error) {
	if c.spool != nil {
		err = errors.Join(err, c.spool.Close(), os.Remove(c.spool.Name()))
	}
	if c.close != nil {
		err = errors.Join(err, c.close())
	}
	return err
}
