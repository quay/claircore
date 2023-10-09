package poolstats

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
	stater := &mockStater{mockStats}
	staterfn := func() stat { return stater.Stat() }
	testObject := newCollector(staterfn, t.Name())
	want := strings.NewReader(`# HELP pgxpool_acquire_count Cumulative count of successful acquires from the pool.
# TYPE pgxpool_acquire_count counter
pgxpool_acquire_count{application_name="TestCollect"} 1
# HELP pgxpool_acquire_duration_seconds_total Total duration of all successful acquires from the pool in nanoseconds.
# TYPE pgxpool_acquire_duration_seconds_total counter
pgxpool_acquire_duration_seconds_total{application_name="TestCollect"} 2
# HELP pgxpool_acquired_conns Number of currently acquired connections in the pool.
# TYPE pgxpool_acquired_conns gauge
pgxpool_acquired_conns{application_name="TestCollect"} 3
# HELP pgxpool_canceled_acquire_count Cumulative count of acquires from the pool that were canceled by a context.
# TYPE pgxpool_canceled_acquire_count counter
pgxpool_canceled_acquire_count{application_name="TestCollect"} 4
# HELP pgxpool_constructing_conns Number of conns with construction in progress in the pool.
# TYPE pgxpool_constructing_conns gauge
pgxpool_constructing_conns{application_name="TestCollect"} 5
# HELP pgxpool_empty_acquire Cumulative count of successful acquires from the pool that waited for a resource to be released or constructed because the pool was empty.
# TYPE pgxpool_empty_acquire counter
pgxpool_empty_acquire{application_name="TestCollect"} 6
# HELP pgxpool_idle_conns Number of currently idle conns in the pool.
# TYPE pgxpool_idle_conns gauge
pgxpool_idle_conns{application_name="TestCollect"} 7
# HELP pgxpool_max_conns Maximum size of the pool.
# TYPE pgxpool_max_conns gauge
pgxpool_max_conns{application_name="TestCollect"} 8
# HELP pgxpool_total_conns Total number of resources currently in the pool. The value is the sum of ConstructingConns, AcquiredConns, and IdleConns.
# TYPE pgxpool_total_conns gauge
pgxpool_total_conns{application_name="TestCollect"} 9
`)

	ls, err := testutil.CollectAndLint(testObject)
	if err != nil {
		t.Error(err)
	}
	for _, l := range ls {
		t.Log(l)
	}
	if err := testutil.CollectAndCompare(testObject, want); err != nil {
		t.Error(err)
	}
}
