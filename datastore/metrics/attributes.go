package metrics

import "go.opentelemetry.io/otel/attribute"

var (
	DeltaKey     = attribute.Key("delta_update")
	FailedKey    = attribute.Key("failed")
	OperationKey = attribute.Key("operation")
	QueryKey     = attribute.Key("query")
)

func Delta(d bool) attribute.KeyValue {
	return DeltaKey.Bool(d)
}

func Failed(err error) attribute.KeyValue {
	return FailedKey.Bool(err != nil)
}

func Operation(op string) attribute.KeyValue {
	return OperationKey.String(op)
}

func Query(which string) attribute.KeyValue {
	return QueryKey.String(which)
}
