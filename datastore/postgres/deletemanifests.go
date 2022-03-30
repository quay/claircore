package postgres

import (
	"context"

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
	rm, err := s.deleteManifests(ctx, d)
	if err != nil {
		return nil, err
	}
	return rm, s.layerCleanup(ctx)
}

func (s *IndexerStore) deleteManifests(ctx context.Context, d []claircore.Digest) ([]claircore.Digest, error) {
	const deleteManifest = `DELETE FROM manifest WHERE hash = ANY($1::TEXT[]) RETURNING manifest.hash;`
	var err error
	defer promTimer(deleteManifestsDuration, "deleteManifest", &err)()
	defer func(e *error) {
		deleteManifestsCounter.WithLabelValues("deleteManifest", success(*e)).Inc()
	}(&err)
	rows, err := s.pool.Query(ctx, deleteManifest, digestSlice(d))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rm := make([]claircore.Digest, 0, len(d)) // May over-allocate, but at least it's only doing it once.
	for rows.Next() {
		i := len(rm)
		rm = rm[:i+1]
		err = rows.Scan(&rm[i])
		if err != nil {
			return nil, err
		}
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Int("count", len(rm)).
		Int("nonexistant", len(d)-len(rm)).
		Msg("deleted manifests")
	return rm, nil
}

func (s *IndexerStore) layerCleanup(ctx context.Context) (err error) {
	const layerCleanup = `DELETE FROM layer WHERE NOT EXISTS (SELECT FROM manifest_layer WHERE manifest_layer.layer_id = layer.id);`
	defer promTimer(deleteManifestsDuration, "layerCleanup", &err)()
	tag, err := s.pool.Exec(ctx, layerCleanup)
	deleteManifestsCounter.WithLabelValues("layerCleanup", success(err)).Inc()
	if err != nil {
		return err
	}
	zlog.Debug(ctx).
		Int64("count", tag.RowsAffected()).
		Msg("deleted layers")
	return nil
}
