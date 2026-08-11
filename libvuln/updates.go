package libvuln

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore/postgres"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/jsonblob"
)

// BUG(hank) The OfflineImport function is a wart, needed to work around
// some package namespacing issues. It should get refactored if claircore
// gets merged into clair.

// OfflineImport takes the format written into the io.Writer provided to
// NewOfflineUpdater and imports the contents into the provided pgxpool.Pool.
//
// The format provided on "in" should be the same output from [jsonblob.Store], with
// any compression undone.
func OfflineImport(ctx context.Context, pool *pgxpool.Pool, in io.Reader) error {
	s := postgres.NewMatcherStore(pool)
	ld, err := jsonblob.NewLoader(ctx, in)
	if err != nil {
		return err
	}
	vulns, err := s.GetUpdateOperations(ctx, driver.VulnerabilityKind)
	if err != nil {
		return err
	}
	enrichers, err := s.GetUpdateOperations(ctx, driver.EnrichmentKind)
	if err != nil {
		return err
	}

	for e, seq := range ld.All() {
		l := slog.With("updater", e.Updater)
		var check []driver.UpdateOperation
		switch e.Kind {
		case driver.VulnerabilityKind:
			check = vulns[e.Updater]
		case driver.EnrichmentKind:
			check = enrichers[e.Updater]
		}
		seen := slices.ContainsFunc(check, func(op driver.UpdateOperation) bool {
			return op.Fingerprint == e.Fingerprint
		})
		if seen {
			l.InfoContext(ctx, "fingerprint match, skipping")
			continue
		}

		l.InfoContext(ctx, "new update")
		var ref uuid.UUID
		var vulnCt, enrichCt int
		switch e.Kind {
		case driver.VulnerabilityKind:
			wrap := func(yield func(*claircore.Vulnerability, error) bool) {
				for v := range seq {
					if v == nil {
						if !yield(nil, ld.Err()) {
							return
						}
						continue
					}
					vulnCt++
					if !yield(v, nil) {
						return
					}
					jsonblob.ReturnVulnerability(v)
				}
			}
			ref, err = s.UpdateVulnerabilitiesIter(ctx, e.Updater, e.Fingerprint, wrap)
		case driver.EnrichmentKind:
			wrap := func(yield func(*driver.EnrichmentRecord, error) bool) {
				for _, e := range seq {
					if e == nil {
						if !yield(nil, ld.Err()) {
							return
						}
						continue
					}
					enrichCt++
					if !yield(e, nil) {
						return
					}
					jsonblob.ReturnEnrichment(e)
				}
			}
			ref, err = s.UpdateEnrichmentsIter(ctx, e.Updater, e.Fingerprint, wrap)
		default:
			panic("unreachable")
		}
		if err == nil {
			l.InfoContext(
				ctx, "update imported",
				"ref", ref,
				"vuln_count", vulnCt,
				"enrichment_count", enrichCt,
			)
		} else {
			l.InfoContext(ctx, "update failed", "reason", err)
			break
		}
	}

	if err := errors.Join(err, ld.Err()); err != nil {
		return err
	}
	return nil
}
