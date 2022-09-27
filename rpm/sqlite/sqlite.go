// Package sqlite extracts RPM package information from SQLite databases.
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed" // embed a sql statement
	"fmt"
	"io"
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

// AllHeaders returns ReaderAts for all RPM headers in the database.
func (db *RPMDB) AllHeaders(ctx context.Context) ([]io.ReaderAt, error) {
	// Keys are sorted coming out of this query.
	rows, err := db.db.QueryContext(ctx, allpackages)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var r []io.ReaderAt
	var hnum int64
	for rows.Next() {
		blob := make([]byte, 0, 4*4096) // Eyeballing a good initial capacity; do some profiling.
		// As an alternative, this function could allocate one large buffer and subslice it for each
		// Scan call, then use io.SectionReaders for the returned []io.ReaderAt.
		if err := rows.Scan(&hnum, &blob); err != nil {
			return nil, fmt.Errorf("sqlite: scan error: %w", err)
		}
		r = append(r, bytes.NewReader(blob))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: sql error: %w", err)
	}

	return r, nil
}

//go:embed sql/allpackages.sql
var allpackages string
