package controller

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter  = otel.Meter("github.com/quay/claircore/indexer/controller/v2")
	tracer = otel.Tracer("github.com/quay/claircore/indexer/controller/v2")

	stepCall metric.Int64Counter
)

var metricInit = sync.OnceValue(func() (err error) {
	stepCall, err = meter.Int64Counter("step.count",
		metric.WithUnit("{call}"),
		metric.WithDescription("tktk"),
	)
	if err != nil {
		return err
	}
	return nil
})

var (
	stepAttrKey = attribute.Key("step")
)

func stepAttr(name string) attribute.KeyValue {
	return stepAttrKey.String(name)
}
