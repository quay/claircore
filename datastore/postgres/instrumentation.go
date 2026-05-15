package postgres

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	dsmetrics "github.com/quay/claircore/datastore/metrics"
)

var (
	tracer trace.Tracer
	meter  metric.Meter

	metrics dsmetrics.Metrics
)

func init() {
	const name = `github.com/quay/claircore/datastore/postgres`
	tracer = otel.Tracer(name)
	meter = otel.Meter(name,
		metric.WithInstrumentationVersion(dsmetrics.Version),
	)

	if err := dsmetrics.Init(&metrics, meter); err != nil {
		panic(err)
	}
}
