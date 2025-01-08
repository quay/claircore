// Package sqlite extracts RPM package information from SQLite databases.
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed" // embed a sql statement
	"errors"
	"fmt"
	"io"
	"iter"
	"net/url"
	"runtime"

	_ "modernc.org/sqlite" // register the sqlite driver
)

// RPMDB is a handle to a SQLite RPM database.
type RPMDB struct {
	db *sql.DB
}

// Open opens the named SQLite database and interprets it as an RPM
// database.
//
// Must be a file on-disk. This is a limitation of the underlying SQLite
// library.
//
// The returned RPMDB struct must have its Close method called, or the
// process may panic.
func Open(f string) (*RPMDB, error) {
	u := url.URL{
		Scheme: `file`,
		Opaque: f,
		RawQuery: url.Values{
			"_pragma": {
				"foreign_keys(1)",
				"query_only(1)",
			},
		}.Encode(),
	}
	db, err := sql.Open(`sqlite`, u.String())
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	rdb := RPMDB{db: db}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&rdb, func(rdb *RPMDB) {
		panic(fmt.Sprintf("%s:%d: RPM db not closed", file, line))
	})
	return &rdb, nil
}

// Close releases held resources.
//
// This must be called when the RPMDB is no longer needed, or the
// process may panic.
func (db *RPMDB) Close() error {
	runtime.SetFinalizer(db, nil)
	return db.db.Close()
}

// All returns an [io.ReaderAt] for each rpm header in the RPMDB.
func (db *RPMDB) All(ctx context.Context) (iter.Seq[io.ReaderAt], func() error) {
	// Keys are sorted coming out of this query.
	rows, final := db.db.QueryContext(ctx, allpackages)

	seq := func(yield func(io.ReaderAt) bool) {
		if final != nil {
			return
		}
		defer rows.Close()

		var hnum int64
		for rows.Next() {
			// Eyeballing a good initial capacity; do some profiling.
			blob := make([]byte, 0, 4*4096)
			// As an alternative, this function could allocate one large buffer,
			// copy into it, and use io.SectionReader for the returned
			// io.ReaderAt.
			if err := rows.Scan(&hnum, &blob); err != nil {
				final = fmt.Errorf("sqlite: scan error: %w", err)
				return
			}
			if !yield(bytes.NewReader(blob)) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			final = fmt.Errorf("sqlite: sql error: %w", err)
		}
	}
	return seq, func() error { return final }
}

func (db *RPMDB) Validate(ctx context.Context) error {
	if err := db.db.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: database problem: %w", err)
	}
	var ignore int64
	err := db.db.QueryRow(validate).Scan(&ignore)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("sqlite: not an rpm database: %w", err)
	default:
		return err
	}
	return nil
}

//go:embed sql/allpackages.sql
var allpackages string

//go:embed sql/validate.sql
var validate string
