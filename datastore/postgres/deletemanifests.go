package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/dblock"
)

var (
	deleteManifestsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "deletemanifests_total",
			Help:      "Total number of calls to the DeleteManifests method.",
		},
		[]string{"action", "success"},
	)
	deleteManifestsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "deletemanifests_duration_seconds",
			Help:      "The duration of taken by the DeleteManifests method.",
		},
		[]string{"action", "success"},
	)
)

// ErrLockFail signals that lock acquisition failed.
var errLockFail = errors.New("lock failed")

// DeleteManifests attempts to delete the indicated manifests.
//
// The returned slice indicates the successfully deleted manifests. An error is
// reported if none were able to be deleted.
func (s *IndexerStore) DeleteManifests(ctx context.Context, ds ...claircore.Digest) ([]claircore.Digest, error) {
	const (
		getManifestID  = `SELECT id FROM manifest WHERE hash = $1`
		getLayers      = `SELECT layer_id FROM manifest_layer WHERE manifest_id = $1;`
		deleteManifest = `DELETE FROM manifest WHERE id = $1;`
		deleteLayers   = `DELETE FROM
		layer
	  WHERE
		id IN (
		  SELECT
			l.id
		  FROM
			layer l
			LEFT JOIN manifest_layer ml ON l.id = ml.layer_id
		  WHERE
			l.id = $1
			AND ml.layer_id IS NULL
		);`
		// This is equivalent to the ctxlock command except that it's requesting
		// a transaction-scoped lock.
		tryLock = `SELECT lock FROM pg_try_advisory_xact_lock($1) lock WHERE lock = true;`
	)

	var err error
	defer promTimer(deleteManifestsDuration, "deleteManifest", &err)()
	defer func(e *error) {
		deleteManifestsCounter.WithLabelValues("deleteManifest", success(*e)).Inc()
	}(&err)
	var errs []error
	deletedManifests := make([]claircore.Digest, 0, len(ds))
	for _, d := range ds {
		attemptErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			defer promTimer(deleteManifestsDuration, "deleteLayers", &err)()
			defer func(e *error) {
				deleteManifestsCounter.WithLabelValues("deleteLayers", success(*e)).Inc()
			}(&err)

			// Obtain the manifest lock:
			key := dblock.Keyify(d.String())
			tag, err := tx.Conn().PgConn().ExecParams(ctx, tryLock,
				[][]byte{key}, nil,
				[]int16{1}, nil).Close()
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return errLockFail
			}

			// Get manifest ID
			var manifestID int64
			err = tx.QueryRow(ctx, getManifestID, d).Scan(&manifestID)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, pgx.ErrNoRows):
				// Currently a silent error, go on to the next
				return nil
			default:
				return fmt.Errorf("unable query manifest: %w", err)
			}

			// Get all layer IDs
			lRows, err := tx.Query(ctx, getLayers, manifestID)
			if err != nil {
				return fmt.Errorf("unable to query layers: %w", err)
			}
			defer lRows.Close()
			lIDs := []int64{}
			for lRows.Next() {
				var layerID int64
				err = lRows.Scan(&layerID)
				if err != nil {
					return fmt.Errorf("unable to scan layer ID: %w", err)
				}
				lIDs = append(lIDs, layerID)
			}
			if err := lRows.Err(); err != nil {
				return fmt.Errorf("error reading layer data: %w", err)
			}

			// Delete manifest
			_, err = tx.Exec(ctx, deleteManifest, manifestID)
			if err != nil {
				return fmt.Errorf("unable to delete manifest: %w", err)
			}
			// Delete eligible layers
			for _, lID := range lIDs {
				tag, err := tx.Exec(ctx, deleteLayers, lID)
				if err != nil {
					return fmt.Errorf("unable check layer usage: %w", err)
				}
				ra := tag.RowsAffected()
				slog.DebugContext(ctx, "deleted layers for manifest",
					"count", ra,
					"manifest", d)
			}
			deletedManifests = append(deletedManifests, d)
			return nil
		})
		switch {
		case attemptErr == nil:
		case errors.Is(attemptErr, errLockFail):
			slog.DebugContext(ctx, "unable to obtain lock", "manifest", d)
		default:
			errs = append(errs, fmt.Errorf("%s: %w", d, attemptErr))
		}
	}
	slog.DebugContext(ctx, "deleted manifests",
		"count", len(deletedManifests),
		"nonexistant", len(ds)-len(deletedManifests))
	if len(deletedManifests) == 0 {
		err = errors.Join(errs...)
		return nil, err
	}
	if len(errs) > 0 {
		slog.WarnContext(ctx, "unexpected errors", "reason", errs)
	}
	return deletedManifests, nil
}
