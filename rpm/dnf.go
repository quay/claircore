package rpm

import (
	"context"
	"database/sql"
	_ "embed" // embed query
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/quay/zlog"
	_ "modernc.org/sqlite" // register the sqlite driver
)

// BUG(hank) The dnf mapping is less useful than it could be because there's no
// reliable way to turn the "repoid" that it reports into something with meaning
// outside of the Red Hat build system's builder's context. See [CLAIRDEV-45]
// for more information.
//
// [CLAIRDEV-45]: https://issues.redhat.com/browse/CLAIRDEV-45

// RepoMap reports the latest nevra → repoid mapping, as extracted from the dnf
// or dnf5 database. If the layer is known to have nonsense repoids, nothing is
// reported.
func repoMap(ctx context.Context, sys fs.FS) (map[string]string, error) {
	var toOpen string
	var isdnf5 bool
Look:
	for i, p := range []string{
		`usr/lib/sysimage/libdnf5/transaction_history.sqlite`,
		`var/lib/dnf/history.sqlite`,
	} {
		switch _, err := fs.Stat(sys, p); {
		case errors.Is(err, nil):
			toOpen = p
			isdnf5 = i == 0
			break Look
		case errors.Is(err, fs.ErrNotExist): // OK
		default:
			return nil, fmt.Errorf("rpm: unexpected error opening dnf history: %w", err)
		}
	}
	if toOpen == "" {
		// Nothing found.
		return nil, nil
	}
	if fi, err := fs.Stat(sys, `root/buildinfo/content_manifests`); errors.Is(err, nil) && fi.IsDir() {
		// This is a RHEL layer, skip.
		return nil, nil
	}

	zlog.Debug(ctx).
		Str("path", toOpen).
		Bool("is-5", isdnf5).
		Msg("found dnf history database")
	r, err := sys.Open(toOpen)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		return nil, fmt.Errorf("rpm: unexpected error opening dnf history: %w", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close tarfs sqlite db")
		}
	}()

	// Currently needs to be linked into the filesystem.
	// See also: quay/claircore#720
	f, err := os.CreateTemp(os.TempDir(), `dnf.sqlite.*`)
	if err != nil {
		return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil {
			zlog.Error(ctx).Err(err).Msg("unable to unlink sqlite db")
		}
		if err := f.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close sqlite db")
		}
	}()
	zlog.Debug(ctx).Str("file", f.Name()).Msg("copying sqlite db out of tar")
	if _, err := io.Copy(f, r); err != nil {
		return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
	}

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		return nil, fmt.Errorf("rpm: error reading sqlite db: %w", err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, queryFinalState, removedEnum(isdnf5))
	if err != nil {
		return nil, fmt.Errorf("rpm: error querying dnf database: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("error closing rows object")
		}
	}()

	ret := make(map[string]string)
	var k, v string
	for rows.Next() {
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("rpm: error reading dnf database: %w", err)
		}
		ret[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rpm: error reading dnf database: %w", err)
	}

	return ret, nil
}

// RemovedEnum reports the enum for a "removed" action for the indicated
// database version.
func removedEnum(is5 bool) int {
	// Defined here:
	// https://github.com/rpm-software-management/dnf5/blob/13886935418e28482de7b675169482b85303845d/include/libdnf/transaction/transaction_item_action.hpp#L35
	if is5 {
		return 5
	}
	// Defined here:
	// https://github.com/rpm-software-management/libdnf/blob/93759bc5cac262906e52b6a173d7b157914ec29e/libdnf/transaction/Types.hpp#L45
	return 8
}

// QueryFinalState returns (nerva, repoid) rows and takes a single argument, the
// "removed" enum to disregard.
//
//go:embed dnf_finalstate.sql
var queryFinalState string
