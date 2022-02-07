package poolstats

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type mockStater struct {
	stats stat
}

func (m *mockStater) Stat() stat {
	return m.stats
}

var _ stat = (*pgxStatMock)(nil)

type pgxStatMock struct {
	acquireCount         int64
	acquireDuration      time.Duration
	canceledAcquireCount int64
	emptyAcquireCount    int64
	acquiredConns        int32
	constructingConns    int32
	idleConns            int32
	maxConns             int32
	totalConns           int32
}

func (m *pgxStatMock) AcquireCount() int64 {
	return m.acquireCount
}

func (m *pgxStatMock) AcquireDuration() time.Duration {
	return m.acquireDuration
}

func (m *pgxStatMock) AcquiredConns() int32 {
	return m.acquiredConns
}

func (m *pgxStatMock) CanceledAcquireCount() int64 {
	return m.canceledAcquireCount
}

func (m *pgxStatMock) ConstructingConns() int32 {
	return m.constructingConns
}

func (m *pgxStatMock) EmptyAcquireCount() int64 {
	return m.emptyAcquireCount
}

func (m *pgxStatMock) IdleConns() int32 {
	return m.idleConns
}

func (m *pgxStatMock) MaxConns() int32 {
	return m.maxConns
}

func (m *pgxStatMock) TotalConns() int32 {
	return m.totalConns
}

func TestDescribe(t *testing.T) {
	expectedDescriptorCount := 9
	timeout := time.After(time.Second * 5)
	stater := &mockStater{&pgxStatMock{}}
	statFn := func() stat { return stater.Stat() }
	testObject := newCollector(statFn, t.Name())

	ch := make(chan *prometheus.Desc)
	go testObject.Describe(ch)

	uniqueDescriptors := make(map[string]struct{})
	var i int
	for i = 0; i < expectedDescriptorCount; i++ {
		select {
		case desc := <-ch:
			uniqueDescriptors[desc.String()] = struct{}{}
		case <-timeout:
			t.Fatalf("timed out wait for %d'th descriptor", i)
		}
	}
	if got, want := expectedDescriptorCount-i, 0; got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
	if len(uniqueDescriptors) != expectedDescriptorCount {
		t.Errorf("Expected %d descriptors to be registered but there were %d", expectedDescriptorCount, len(uniqueDescriptors))
	}
}

func TestCollect(t *testing.T) {
	expectedMetricValues := map[string]float64{
		"pgxpool_acquire_count":                  1,
		"pgxpool_acquire_duration_seconds_total": 2,
		"pgxpool_acquired_conns":                 3,
		"pgxpool_canceled_acquire_count":         4,
		"pgxpool_constructing_conns":             5,
		"pgxpool_empty_acquire":                  6,
		"pgxpool_idle_conns":                     7,
		"pgxpool_max_conns":                      8,
		"pgxpool_total_conns":                    9,
	}

	mockStats := &pgxStatMock{
		acquireCount:         int64(1),
		acquireDuration:      time.Second * 2,
		acquiredConns:        int32(3),
		canceledAcquireCount: int64(4),
		constructingConns:    int32(5),
		emptyAcquireCount:    int64(6),
		idleConns:            int32(7),
		maxConns:             int32(8),
		totalConns:           int32(9),
	}
	expectedMetricCount := 9
	timeout := time.After(time.Second * 5)
	stater := &mockStater{mockStats}
	staterfn := func() stat { return stater.Stat() }
	testObject := newCollector(staterfn, t.Name())

	ch := make(chan prometheus.Metric)
	go testObject.Collect(ch)

	expectedMetricCountRemaining := expectedMetricCount
	for expectedMetricCountRemaining != 0 {
		select {
		case metric := <-ch:
			pb := &dto.Metric{}
			metric.Write(pb)
			description := metric.Desc().String()
			metricExpected := false
			for expectedMetricName, expectedMetricValue := range expectedMetricValues {
				if strings.Contains(description, expectedMetricName) {
					var value float64
					if pb.GetCounter() != nil {
						value = *pb.GetCounter().Value
					}
					if pb.GetGauge() != nil {
						value = *pb.GetGauge().Value
					}
					if value != expectedMetricValue {
						t.Errorf("Expected the '%s' metric to be %g but was %g", expectedMetricName, expectedMetricValue, value)
					}
					metricExpected = true
					break
				}
			}
			if !metricExpected {
				t.Errorf("Unexpected description: %s", description)
			}
			expectedMetricCountRemaining--
		case <-timeout:
			t.Fatalf("Test timed out while there were still %d descriptors expected", expectedMetricCountRemaining)
		}
	}
	if expectedMetricCountRemaining != 0 {
		t.Errorf("Expected all metrics to be found but %d was not", expectedMetricCountRemaining)
	}
}
