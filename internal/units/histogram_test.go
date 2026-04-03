package units

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBucketSeq(t *testing.T) {
	tt := []struct {
		Name string
		Want []float64
	}{
		{
			"Buckets",
			[]float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},
		},
		{
			"LargeBuckets",
			[]float64{0.05, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10, 25, 50, 75, 100},
		},
		{
			"VeryLargeBuckets",
			[]float64{0.1, 0.2, 0.5, 1, 1.5, 2, 5, 10, 15, 20, 50, 100, 150, 200},
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			want := tc.Want
			got := BucketBoundaries(want[0], len(want))

			if !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}
