package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
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

func (s *IndexerStore) DeleteManifests(ctx context.Context, ds ...claircore.Digest) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/DeleteManifests")
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
	)

	var err error
	defer promTimer(deleteManifestsDuration, "deleteManifest", &err)()
	defer func(e *error) {
		deleteManifestsCounter.WithLabelValues("deleteManifest", success(*e)).Inc()
	}(&err)
	deletedManifests := make([]claircore.Digest, 0, len(ds))
	for _, d := range ds {
		pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			defer promTimer(deleteManifestsDuration, "deleteLayers", &err)()
			defer func(e *error) {
				deleteManifestsCounter.WithLabelValues("deleteLayers", success(*e)).Inc()
			}(&err)
			// Get manifest ID
			var manifestID int64
			err := tx.QueryRow(ctx, getManifestID, d).Scan(&manifestID)
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
				zlog.Debug(ctx).
					Int64("count", ra).
					Str("manifest", d.String()).
					Msg("deleted layers for manifest")
			}
			deletedManifests = append(deletedManifests, d)
			return nil
		})
	}
	zlog.Debug(ctx).
		Int("count", len(deletedManifests)).
		Int("nonexistant", len(ds)-len(deletedManifests)).
		Msg("deleted manifests")
	return deletedManifests, nil
}
