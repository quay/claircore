package libvuln

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
)

// OfflineImport takes the format written into the io.Writer provided to
// NewOfflineUpdater and imports the contents into the provided pgxpool.Pool.
//
// The format provided on "in" should be the same output from [jsonblob.Store], with
// any compression undone.
func OfflineImport(ctx context.Context, pool *pgxpool.Pool, in io.Reader) error {
	// BUG(hank) The OfflineImport function is a wart, needed to work around
	// some package namespacing issues. It should get refactored if claircore
	// gets merged into clair.
	ctx = zlog.ContextWithValues(ctx, "component", "libvuln/OfflineImporter")

	s := postgres.NewMatcherStore(pool)
	l, err := jsonblob.Load(ctx, in)
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
		var ref uuid.UUID
		if e.Enrichment != nil {
			if ref, err = s.UpdateEnrichments(ctx, e.Updater, e.Fingerprint, e.Enrichment); err != nil {
				return fmt.Errorf("updating enrichements: %w", err)
			}
		}
		if e.Vuln != nil {
			if ref, err = s.UpdateVulnerabilities(ctx, e.Updater, e.Fingerprint, e.Vuln); err != nil {
				return fmt.Errorf("updating vulnerabilities: %w", err)
			}
		}
		zlog.Info(ctx).
			Str("updater", e.Updater).
			Str("ref", ref.String()).
			Int("vuln_count", len(e.Vuln)).
			Int("enrichment_count", len(e.Enrichment)).
			Msg("update imported")
	}
	if err := l.Err(); err != nil {
		return err
	}
	return nil
}
