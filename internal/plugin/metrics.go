package plugin

import (
	"context"

	"github.com/jackc/puddle/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Otel tracer and meter for this package.
var (
	tracer = otel.GetTracerProvider().Tracer(`github.com/quay/claircore/internal/plugin`)
	meter  = otel.GetMeterProvider().Meter(`github.com/quay/claircore/internal/plugin`)
)

// Cumulative metrics on a named pool.
var (
	poolAcquireCount = must(meter.Int64ObservableCounter("pool.plugins.acquire_count",
		metric.WithUnit("{request}"),
		metric.WithDescription(`Reports the cumulative count of successful acquires from the pool.`)))
	poolAcquireDuration = must(meter.Float64ObservableCounter("pool.plugins.acquire_duration",
		metric.WithUnit("s"),
		metric.WithDescription(`Reports the total duration of all successful acquires from the pool.`)))
	poolCanceledAcquireCount = must(meter.Int64ObservableCounter("pool.plugins.canceled_acquire_count",
		metric.WithUnit("{request}"),
		metric.WithDescription(`Reports the cumulative count of acquires from the pool that were canceled by a context.`)))
	poolEmptyAcquireCount = must(meter.Int64ObservableCounter("pool.plugins.empty_acquire_count",
		metric.WithUnit("{request}"),
		metric.WithDescription(`Reports the cumulative count of successful acquires from the pool that waited for a resource to be released or constructed because the pool was empty.`)))
)

// Instantaneous metrics on a named pool.
var (
	poolUsage = must(meter.Int64ObservableUpDownCounter("pool.plugins.usage",
		metric.WithUnit("{plugin}"),
		metric.WithDescription(`Reports the number of resources in the pool by state.`)))
	poolMax = must(meter.Int64ObservableUpDownCounter("pool.plugins.max",
		metric.WithUnit("{plugin}"),
		metric.WithDescription(`Reports the maximum size of the pool.`)))
)

// The attributes for the "pool.plugins.usage" meter.
var (
	usedAttr = attribute.NewSet(attribute.String("state", "used"))
	idleAttr = attribute.NewSet(attribute.String("state", "idle"))
	ctorAttr = attribute.NewSet(attribute.String("state", "constructing"))
)

// Must returns the value if the error is not nil, panicking otherwise.
func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

// MetricsSetup registers a callback to export stats for the passed pool and
// name.
//
// This method assumes it's being called in the constructor. It does not take
// any locks.
func (p *Pool[T]) metricsSetup(name string, np *puddle.Pool[T]) error {
	attrs := attribute.NewSet(
		attribute.String("plugin.name", name),
	)
	cb := func(ctx context.Context, o metric.Observer) error {
		s := np.Stat()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		o.ObserveInt64(poolAcquireCount, s.AcquireCount(), metric.WithAttributeSet(attrs))
		o.ObserveFloat64(poolAcquireDuration, s.AcquireDuration().Seconds(), metric.WithAttributeSet(attrs))
		o.ObserveInt64(poolCanceledAcquireCount, s.CanceledAcquireCount(), metric.WithAttributeSet(attrs))
		o.ObserveInt64(poolEmptyAcquireCount, s.EmptyAcquireCount(), metric.WithAttributeSet(attrs))
		o.ObserveInt64(poolMax, int64(s.MaxResources()), metric.WithAttributeSet(attrs))
		o.ObserveInt64(poolUsage, int64(s.AcquiredResources()), metric.WithAttributeSet(attrs), metric.WithAttributeSet(usedAttr))
		o.ObserveInt64(poolUsage, int64(s.IdleResources()), metric.WithAttributeSet(attrs), metric.WithAttributeSet(idleAttr))
		o.ObserveInt64(poolUsage, int64(s.ConstructingResources()), metric.WithAttributeSet(attrs), metric.WithAttributeSet(ctorAttr))
		return nil
	}
	reg, err := meter.RegisterCallback(cb,
		poolAcquireCount,
		poolAcquireDuration,
		poolCanceledAcquireCount,
		poolEmptyAcquireCount,
		poolUsage,
		poolMax,
	)
	if err != nil {
		return err
	}
	p.close[name] = reg
	return nil
}
