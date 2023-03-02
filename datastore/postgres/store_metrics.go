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
	metricLabels  = []string{"query", "success", "db"}
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

//go:embed queries/***/*.sql
var queries embed.FS

type query struct {
	SQL string

	labels prometheus.Labels
	timer  *prometheus.Timer
}

func newQuery(ctx context.Context, db string, name string) query {
	b, err := fs.ReadFile(queries, path.Join("queries", db, name+".sql"))
	if err != nil {
		panic(err)
	}

	return query{
		SQL:    string(b),
		labels: prometheus.Labels{"query": name, "db": db},
	}
}

func (q *query) Start(err *error) func() {
	q.timer = prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		databaseTimer.With(q.labels).Observe(v)
	}))
	return func() {
		if q.timer == nil {
			return
		}
		q.labels["success"] = strconv.FormatBool(errors.Is(*err, nil))
		databaseCounter.With(q.labels).Inc()
		if q.timer != nil {
			q.timer.ObserveDuration()
		}
		q.timer = nil
	}
}
