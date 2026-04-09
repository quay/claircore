package tarfs

import (
	"runtime/pprof"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Metrics singletons.
var (
	tracer trace.Tracer
	meter  metric.Meter
)

// FsCounter is the metrics for the [New] function.
var fsCounter metric.Int64Counter

// Profile is a [pprof.Profile] for tracking FS objects.
var profile *pprof.Profile

func init() {
	const pkgname = `github.com/quay/claircore/pkg/tarfs`
	tracer = otel.Tracer(pkgname)
	meter = otel.Meter(pkgname)
	profile = pprof.NewProfile(pkgname + ".FS")

	var err error
	fsCounter, err = meter.Int64Counter("fs.creation.count",
		metric.WithDescription("total number of tarfs.FS objects constructed"),
		metric.WithUnit("{instance}"),
	)
	if err != nil {
		panic(err)
	}
}
