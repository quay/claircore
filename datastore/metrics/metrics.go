// Package metrics holds helpers to register datastore metrics.
//
// This is split out so that datastore implementations can "just" provide the
// meters and have them configured uniformly.
package metrics

import (
	"sync"

	"go.opentelemetry.io/otel/metric"
)

var (
	// NormalBucketBoundaries ...
	//
	// 	0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10
	NormalBucketBoundaries = sync.OnceValue(func() []float64 {
		return []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
	})
	// LongBucketBoundaries ...
	//
	// 	0.05, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10, 25, 50, 75, 100
	LongBucketBoundaries = sync.OnceValue(func() []float64 {
		n := NormalBucketBoundaries()
		l := make([]float64, len(n))
		copy(l, n)
		for i := range l {
			l[i] *= 10
		}
		return l
	})
	// VeryLongBucketBoundaries ...
	//
	// 	0.1, 0.2, 0.5, 1, 1.5, 2, 5, 10, 15, 20, 50, 100, 150, 200, 300
	VeryLongBucketBoundaries = sync.OnceValue(func() []float64 {
		n := NormalBucketBoundaries()
		v := make([]float64, len(n))
		copy(v, n)
		for i := range v {
			v[i] *= 20
		}
		return append(v, 300)
	})
)

const Version = `0.1.0`

type Metrics struct {
	UpdateVulnerabilities struct {
		CallDuration  metric.Float64Histogram
		QueryCounter  metric.Int64Counter
		QueryDuration metric.Float64Histogram
	}
}

func Init(m *Metrics, meter metric.Meter) (err error) {
	if err := updateVulnerabilities(m, meter); err != nil {
		return err
	}

	return nil
}

const (
	prefix = `claircore.datastore.`
)

func updateVulnerabilities(m *Metrics, meter metric.Meter) (err error) {
	m.UpdateVulnerabilities.CallDuration, err = meter.Float64Histogram(
		prefix+"update_vulnerabilities.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of UpdateVulnerabilities requests."),
		metric.WithExplicitBucketBoundaries(NormalBucketBoundaries()...),
	)
	if err != nil {
		return err
	}

	m.UpdateVulnerabilities.QueryCounter, err = meter.Int64Counter(
		prefix+"update_vulnerabilities.queries",
		metric.WithUnit("{query}"),
		metric.WithDescription("Number of UpdateVulnerabilities database queries."),
	)
	if err != nil {
		return err
	}

	m.UpdateVulnerabilities.QueryDuration, err = meter.Float64Histogram(
		prefix+"update_vulnerabilities.query.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of UpdateVulnerabilities database queries."),
		metric.WithExplicitBucketBoundaries(NormalBucketBoundaries()...),
	)
	if err != nil {
		return err
	}

	return nil
}
