package httpreader

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestContentRange(t *testing.T) {
	t.Parallel()
	tt := []struct {
		In   string
		Want ContentRange
		Err  bool
	}{
		{
			In:   `bytes */64`,
			Want: ContentRange{First: -1, Last: -1, Length: 64},
		},
		{
			In:   `nonsense`,
			Want: ContentRange{First: -1, Last: -1, Length: -1},
			Err:  true,
		},
		{
			In:   `bytes 0-63/64`,
			Want: ContentRange{First: 0, Last: 63, Length: 64},
		},
		{
			In:   `bytes 0-63/*`,
			Want: ContentRange{First: 0, Last: 63, Length: -1},
		},
	}

	for _, tc := range tt {
		t.Run("", func(t *testing.T) {
			t.Logf("In: %+q", tc.In)
			var got ContentRange
			err := got.Parse(tc.In)
			if err != nil {
				t.Logf("error: %v", err)
			}
			if tc.Err == (err == nil) {
				t.Fail()
			}
			t.Logf("got: %d/%d/%d", got.First, got.Last, got.Length)
			if !cmp.Equal(got, tc.Want) {
				t.Error(cmp.Diff(got, tc.Want))
			}
		})
	}
}
