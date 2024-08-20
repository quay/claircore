package cvss

import (
	"testing"
)

func TestV3(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		Error[V3, V3Metric, *V3](t, LoadErrorFixture(t, "testdata/v3_error.list"))
	})

	t.Run("Roundtrip", func(t *testing.T) {
		Roundtrip[V3, V3Metric, *V3](t, LoadRoundtripFixture(t, "testdata/v3_roundtrip.list"))
	})
	t.Run("Score", func(t *testing.T) {
		t.Run("3.0", func(t *testing.T) {
			Score[V3, V3Metric, *V3](t, LoadScoreFixture(t, "testdata/v30_score.list"))
		})
		t.Run("3.1", func(t *testing.T) {
			Score[V3, V3Metric, *V3](t, LoadScoreFixture(t, "testdata/v31_score.list"))
		})
	})
}
