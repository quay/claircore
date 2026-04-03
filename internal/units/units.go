package units

import (
	"go.opentelemetry.io/otel/metric"
)

// Various common units.
var (
	Byte   = metric.WithUnit("By")
	Second = metric.WithUnit("s")
)

// Count returns a [metric.InstrumentOption] for integer counts of something.
//
// The passed string should be singular and not include braces.
func Count(singular string) metric.InstrumentOption {
	return metric.WithUnit("{" + singular + "}")
}
