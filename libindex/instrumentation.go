package libindex

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/internal/units"
)

const i14nName = "github.com/quay/claircore/libindex"

var (
	tracer trace.Tracer
	meter  metric.Meter
)

func init() {
	tracer = otel.Tracer(i14nName)
	meter = otel.Meter(i14nName)
}

var (
	pathKey               = attribute.Key("path")
	compressedKey         = attribute.Key("compressed")
	failedKey             = attribute.Key("failed")
	cacheHitKey           = attribute.Key("cache_hit")
	payloadTypeKey        = attribute.Key("payload.content_type.header")
	payloadTypeFixedKey   = attribute.Key("payload.content_type.detected")
	payloadCompressionKey = attribute.Key("payload.compression.detected")
)

func pathAttr(p string) attribute.KeyValue {
	return pathKey.String(p)
}

func compressedAttr(b bool) attribute.KeyValue {
	return compressedKey.Bool(b)
}

func failedAttr(b bool) attribute.KeyValue {
	return failedKey.Bool(b)
}

func cacheHitAttr(b bool) attribute.KeyValue {
	return cacheHitKey.Bool(b)
}

func payloadType(ct string) attribute.KeyValue {
	return payloadTypeKey.String(ct)
}

func payloadTypeFixed(ct string) attribute.KeyValue {
	return payloadTypeFixedKey.String(ct)
}

func payloadCompression(c fmt.Stringer) attribute.KeyValue {
	return payloadCompressionKey.String(c.String())
}

// ArenaMetrics holds metrics for a single [RemoteFetchArena].
//
// The resulting metrics are scoped for the arena.
type arenaMetrics struct {
	sizes    metric.Int64Histogram
	duration metric.Float64Histogram
	requests metric.Int64Counter
	entries  metric.Registration
}

// SetupMetrics does setup for metrics in the receiver.
func (a *RemoteFetchArena) setupMetrics(dir string) (err error) {
	meter := otel.Meter(i14nName,
		metric.WithInstrumentationAttributes(
			pathAttr(dir),
		),
	)

	a.metrics.sizes, err = meter.Int64Histogram("fetcher.layer_size",
		metric.WithDescription("Size of container layers."),
		units.Byte,
	)
	if err != nil {
		return err
	}
	a.metrics.duration, err = meter.Float64Histogram("fetcher.duration",
		metric.WithDescription("Duration of fetcher requests."),
		units.Second,
		units.LargeBuckets,
	)
	if err != nil {
		return err
	}
	a.metrics.requests, err = meter.Int64Counter("fetcher.requests",
		metric.WithDescription("Number of fetcher requests."),
		units.Count("request"),
	)
	if err != nil {
		return err
	}

	entries, err := meter.Int64ObservableGauge("fetcher.cache.entries",
		metric.WithDescription("Number of live entries in the layer cache."),
		units.Count("entry"),
	)
	if err != nil {
		return err
	}
	a.metrics.entries, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(entries, int64(a.files.Len()))
		return nil
	}, entries)
	if err != nil {
		return err
	}

	return nil
}

// CompressedSize records a layer's compressed size.
func (m *arenaMetrics) CompressedSize(ctx context.Context, sz int64) {
	m.sizes.Record(ctx, sz, metric.WithAttributes(compressedAttr(true)))
}

// UncompressedSize records a layer's uncompressed (on-disk) size.
func (m *arenaMetrics) UncompressedSize(ctx context.Context, sz int64) {
	m.sizes.Record(ctx, sz, metric.WithAttributes(compressedAttr(false)))
}

// Request returns a function to record one fetch request.
//
// This method counts total requests and durations.
func (m *arenaMetrics) Request() func(ctx context.Context, failed, cacheHit bool) {
	start := time.Now()
	return func(ctx context.Context, failed, cacheHit bool) {
		s := attribute.NewSet(failedAttr(failed), cacheHitAttr(cacheHit))
		m.duration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributeSet(s))
		m.requests.Add(ctx, 1, metric.WithAttributeSet(s))
	}
}
