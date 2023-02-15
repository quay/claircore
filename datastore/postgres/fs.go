package postgres

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"path"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricLabels  = []string{"query", "success"}
	databaseTimer = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "claircore",
		Subsystem: "datastore_postgres",
		Name:      "query_duration_seconds",
		Help:      "Database query duration for noted query, including data read time.",
	}, metricLabels)
	databaseCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "claircore",
		Subsystem: "datastore_postgres",
		Name:      "query_total",
		Help:      "Database query count for noted query.",
	}, metricLabels)
)

//go:embed queries/*.sql
var queries embed.FS

func getQuery(ctx context.Context, name string, e *error) (string, func()) {
	b, err := fs.ReadFile(queries, path.Join("queries", name+".sql"))
	if err != nil {
		panic(err)
	}

	ls := prometheus.Labels{"query": name}
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		databaseTimer.With(ls).Observe(v)
	}))
	return string(b), func() {
		ls["success"] = strconv.FormatBool(errors.Is(*e, nil))
		databaseCounter.With(ls).Inc()
		timer.ObserveDuration()
	}
}
