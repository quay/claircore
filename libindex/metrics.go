package libindex

import (
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

func init() {
	tracer = otel.Tracer("github.com/quay/claircore/libindex",
		trace.WithSchemaURL(semconv.SchemaURL),
	)
}
