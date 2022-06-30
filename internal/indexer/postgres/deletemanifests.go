package postgres

import (
	"context"
	_ "embed"
	"runtime/trace"
	"strconv"

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

func (s *store) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "internal/indexer/postgres/DeleteManifests")
	ctx, task := trace.NewTask(ctx, "DeleteManifests")
	defer task.End()
	rm, err := s.deleteManifests(ctx, d)
	if err != nil {
		return nil, err
	}
	return rm, s.layerCleanup(ctx)
}

var (
	//go:embed sql/delete_manifest.sql
	deleteManifestSQL string
	//go:embed sql/layer_cleanup.sql
	layerCleanupSQL string
)

func (s *store) deleteManifests(ctx context.Context, d []claircore.Digest) ([]claircore.Digest, error) {
	const name = "deleteManifest"
	var err error
	defer trace.StartRegion(ctx, name).End()
	defer promTimer(deleteManifestsDuration, name, &err)()
	defer func(e *error) {
		deleteManifestsCounter.WithLabelValues(name, strconv.FormatBool(*e == nil)).Inc()
	}(&err)
	rows, err := s.pool.Query(ctx, deleteManifestSQL, digestSlice(d))
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

func (s *store) layerCleanup(ctx context.Context) (err error) {
	const name = "layerCleanup"
	defer trace.StartRegion(ctx, name).End()
	defer promTimer(deleteManifestsDuration, name, &err)()
	tag, err := s.pool.Exec(ctx, layerCleanupSQL)
	deleteManifestsCounter.WithLabelValues(name, strconv.FormatBool(err == nil)).Inc()
	if err != nil {
		return err
	}
	zlog.Debug(ctx).
		Int64("count", tag.RowsAffected()).
		Msg("deleted layers")
	return nil
}
