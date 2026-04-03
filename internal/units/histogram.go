package units

import (
	"math/big"
	"slices"

	"go.opentelemetry.io/otel/metric"
)

// Buckets as suggested for [request durations].
//
// [request durations]: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration
var Buckets metric.HistogramOption

// LargeBuckets is a 10x multiple of [Buckets].
var LargeBuckets metric.HistogramOption

// VeryLargeBuckets is a 20x multiple [Buckets].
var VeryLargeBuckets metric.HistogramOption

func init() {
	Buckets = metric.WithExplicitBucketBoundaries(BucketBoundaries(0.005, 14)...)
	LargeBuckets = metric.WithExplicitBucketBoundaries(BucketBoundaries(0.05, 14)...)
	VeryLargeBuckets = metric.WithExplicitBucketBoundaries(BucketBoundaries(0.1, 14)...)
}

// BucketBoundaries returns "count" bucket boundaries in the same pattern as the
// semconv suggested bucket boundaries.
func BucketBoundaries(start float64, count int) []float64 {
	// This uses [big.Rat], which is probably not strictly necessary, but avoids
	// needing to do rounding shenanigans. The overhead of the math is also just
	// paid once at setup.
	ten := big.NewRat(10, 1)
	rat := big.NewRat(1, 4)
	steps := []*big.Rat{
		big.NewRat(1, 1),
		big.NewRat(2, 1),
		big.NewRat(3, 1),
	}

	n := new(big.Rat).SetFloat64(start)
	seq := func(yield func(float64) bool) {
		// Yield wrapper: convert the [big.Rat] and check the number of values
		// we're supposed to produce.
		y := func(n *big.Rat) bool {
			v, _ := n.Float64()
			count--
			return yield(v) && count > 0
		}
		if !y(n) {
			return
		}
		n.Mul(n, big.NewRat(2, 1))
		v, incr := new(big.Rat), new(big.Rat)
		for {
			if !y(n) {
				return
			}

			n.Mul(n, ten)
			incr.Mul(n, rat)

			for _, step := range steps {
				v.Mul(incr, step)
				if !y(v) {
					return
				}
			}
		}
	}
	return slices.Collect(seq)
}
