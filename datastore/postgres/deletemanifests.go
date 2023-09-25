package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v4"
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
			Help:      "Total number of database queries issued in the DeleteManifests method.",
		},
		[]string{"query", "success"},
	)
	deleteManifestsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "indexer",
			Name:      "deletemanifests_duration_seconds",
			Help:      "The duration of all queries issued in the DeleteManifests method.",
		},
		[]string{"query", "success"},
	)
)

func (s *IndexerStore) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "datastore/postgres/DeleteManifests")
	return s.deleteManifests(ctx, d)
}

func (s *IndexerStore) deleteManifests(ctx context.Context, ds []claircore.Digest) ([]claircore.Digest, error) {
	const (
		getManifestID      = `SELECT id FROM manifest WHERE hash = $1`
		getLayers          = `SELECT layer_id FROM manifest_layer WHERE manifest_id = $1;`
		getDeletableLayers = `
SELECT l.id FROM layer l 
LEFT JOIN manifest_layer ml 
ON l.id = ml.layer_id 
WHERE l.id = $1
AND ml.layer_id IS NULL;`
		deleteManifest = `DELETE FROM manifest WHERE id = $1;`
		deleteLayers   = `DELETE FROM layer WHERE id = ANY($1);`
	)

	deletedManifests := make([]claircore.Digest, 0, len(ds))
	for _, d := range ds {
		tx, err := s.pool.Begin(ctx)
		defer tx.Rollback(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to start transaction: %w", err)
		}
		// Get manifest ID
		var manifestID int64
		err = tx.QueryRow(ctx, getManifestID, d).Scan(&manifestID)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrNoRows):
			continue
		default:
			return nil, fmt.Errorf("unable query manifest: %w", err)
		}

		// Get all layer IDs
		lRows, err := tx.Query(ctx, getLayers, manifestID)
		if err != nil {
			return nil, fmt.Errorf("unable to query layers: %w", err)
		}
		defer lRows.Close()
		lIDs := []int64{}
		for lRows.Next() {
			var layerID int64
			err = lRows.Scan(&layerID)
			if err != nil {
				return nil, fmt.Errorf("unable to scan layer ID: %w", err)
			}
			lIDs = append(lIDs, layerID)
		}
		lRows.Close()
		// TODO: feedback for how things went
		// Delete manifest
		_, err = tx.Exec(ctx, deleteManifest, manifestID)
		if err != nil {
			return nil, fmt.Errorf("unable to delete manifest: %w", err)
		}
		// Get eligible layers to delete
		lToDelete := []int64{}
		for _, lID := range lIDs {
			var layerID int64
			err := tx.QueryRow(ctx, getDeletableLayers, lID).Scan(&layerID)
			switch {
			case errors.Is(err, nil):
				lToDelete = append(lToDelete, layerID)
			case errors.Is(err, pgx.ErrNoRows):
				// No rows, the layer still exists don't delete
			default:
				return nil, fmt.Errorf("unable check layer usage: %w", err)
			}
		}
		// Delete layers
		_, err = tx.Exec(ctx, deleteLayers, lToDelete)
		if err != nil {
			return nil, fmt.Errorf("unable to delete layers: %w", err)
		}
		err = tx.Commit(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to commit transaction: %w", err)
		}
		// We got here with no errors, it's gone (probably)
		deletedManifests = append(deletedManifests, d)
	}
	return deletedManifests, nil
}
