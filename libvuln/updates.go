package libvuln

import (
	"compress/gzip"
	"context"
	"io"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
)

// OfflineImport takes the format written into the io.Writer provided to
// NewOfflineUpdater and imports the contents into the provided pgxpool.Pool.
func OfflineImport(ctx context.Context, pool *pgxpool.Pool, in io.Reader) error {
	// BUG(hank) The OfflineImport function is a wart, needed to work around
	// some package namespacing issues. It should get refactored if claircore
	// gets merged into clair.
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/OfflineImporter")

	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()

	s := postgres.NewMatcherStore(pool)
	l, err := jsonblob.Load(ctx, gz)
	if err != nil {
		return err
	}

	ops, err := s.GetUpdateOperations(ctx, driver.VulnerabilityKind)
	if err != nil {
		return err
	}

Update:
	for l.Next() {
		e := l.Entry()
		for _, op := range ops[e.Updater] {
			// This only helps if updaters don't keep something that
			// changes in the fingerprint.
			if op.Fingerprint == e.Fingerprint {
				zlog.Info(ctx).
					Str("updater", e.Updater).
					Msg("fingerprint match, skipping")
				continue Update
			}
		}
		ref, err := s.UpdateVulnerabilities(ctx, e.Updater, e.Fingerprint, e.Vuln)
		if err != nil {
			return err
		}
		zlog.Info(ctx).
			Str("updater", e.Updater).
			Str("ref", ref.String()).
			Int("count", len(e.Vuln)).
			Msg("update imported")
	}
	if err := l.Err(); err != nil {
		return err
	}
	return nil
}
