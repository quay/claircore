// Package sqlite extracts RPM package information from SQLite databases.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed" // embed a sql statement
	"fmt"
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

// Packages loads all package headers in the RPMDB and reports [Info]s
// for each.
func (db *RPMDB) Packages(ctx context.Context) ([]Info, error) {
	hs, err := db.loadHeaders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Info, len(hs.key))
	for i, k := range hs.key {
		p := &out[i]
		h := hs.header[k]
		found := false
		for i := range h.Infos {
			e := &h.Infos[i]
			if _, ok := wantTags[e.Tag]; !ok {
				continue
			}
			found = true
			v, err := h.ReadData(ctx, e)
			if err != nil {
				return nil, err
			}
			switch e.Tag {
			case tagName:
				p.Name = v.(string)
			case tagEpoch:
				p.Epoch = int(v.([]int32)[0])
			case tagVersion:
				p.Version = v.(string)
			case tagRelease:
				p.Release = v.(string)
			case tagSourceRPM:
				p.SourceNEVR = v.(string)
			case tagModularityLabel:
				p.Module = v.(string)
			case tagArch:
				p.Arch = v.(string)
			case tagPayloadDigestAlgo:
				p.DigestAlgo = int(v.([]int32)[0])
			case tagPayloadDigest:
				p.Digest = v.([]string)[0]
			case tagSigPGP:
				p.Signature = v.([]byte)
			}
		}
		if !found {
			return nil, fmt.Errorf("rpm/sqlite: martian header %d", k)
		}
	}

	return out, nil
}

// Info is the package information extracted from the RPM header.
type Info struct {
	Name       string
	Version    string
	Release    string
	SourceNEVR string
	Module     string
	Arch       string
	Digest     string
	Signature  []byte // This is a PGP signature packet.
	DigestAlgo int
	Epoch      int
}

var wantTags = map[tag]struct{}{
	tagName:              {},
	tagEpoch:             {},
	tagVersion:           {},
	tagRelease:           {},
	tagSourceRPM:         {},
	tagModularityLabel:   {},
	tagArch:              {},
	tagPayloadDigestAlgo: {},
	tagPayloadDigest:     {},
	tagSigPGP:            {},
}

func (db *RPMDB) loadHeaders(ctx context.Context) (headers, error) {
	// Keys are sorted coming out of this query.
	rows, err := db.db.QueryContext(ctx, allpackages)
	if err != nil {
		return headers{}, err
	}
	defer rows.Close()
	hs := headers{header: make(map[int64]*header)}
	var hnum int64
	for rows.Next() {
		blob := make([]byte, 0, 4*4096) // Eyeballing a good initial capacity; do some profiling.
		if err := rows.Scan(&hnum, &blob); err != nil {
			return headers{}, err
		}
		var h header
		if err := h.Parse(ctx, blob); err != nil {
			return headers{}, err
		}
		hs.header[hnum] = &h
		hs.key = append(hs.key, hnum)
	}
	if err := rows.Err(); err != nil {
		return headers{}, err
	}

	return hs, nil
}

//go:embed sql/allpackages.sql
var allpackages string

type headers struct {
	header map[int64]*header
	key    []int64
}
