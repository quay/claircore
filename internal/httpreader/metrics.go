package httpreader

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter(`github.com/quay/claircore/internal/httpreader`)

var (
	searchCount      metric.Int64Histogram
	searchOriginKey  = attribute.Key("search.origin")
	searchSuccessKey = attribute.Key("search.success")
)

func init() {
	var err error
	searchCount, err = meter.Int64Histogram(
		"search",
		metric.WithDescription("Number of requests made to binary search for the end of a resource"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		panic(err)
	}
}

func searchOrigin(v string) attribute.KeyValue {
	return searchOriginKey.String(v)
}

func searchSuccess(v bool) attribute.KeyValue {
	return searchSuccessKey.Bool(v)
}

func recordSearchCount(ctx context.Context, origin string, reqp *int, okp *bool) {
	searchCount.Record(ctx,
		int64(*reqp),
		metric.WithAttributes(searchOrigin(origin), searchSuccess(*okp)))
}
