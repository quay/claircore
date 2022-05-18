package postgres

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricLint(t *testing.T) {
	lints, err := testutil.GatherAndLint(prometheus.DefaultGatherer)
	if err != nil {
		t.Error(err)
	}
	for _, l := range lints {
		t.Errorf("%s: %s", l.Metric, l.Text)
	}
}
