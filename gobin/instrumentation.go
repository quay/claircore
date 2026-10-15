package gobin

import (
	"go.opentelemetry.io/otel"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	tracer trace.Tracer
	meter  metric.Meter
)

func init() {
	const name = "github.com/quay/claircore/gobin"
	tracer = otel.Tracer(name)
	meter = otel.Meter(name)
}
