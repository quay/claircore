package poolstats

import (
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	_ prometheus.Collector = (*Collector)(nil)
	_ stat                 = (*pgxpool.Stat)(nil)
)

// Stat is the interface implemented by pgxpool.Stat.
type stat interface {
	AcquireCount() int64
	AcquireDuration() time.Duration
	AcquiredConns() int32
	CanceledAcquireCount() int64
	ConstructingConns() int32
	EmptyAcquireCount() int64
	IdleConns() int32
	MaxConns() int32
	TotalConns() int32
}

type staterFunc func() stat

// Collector is a prometheus.Collector that will collect the nine statistics produced by pgxpool.Stat.
type Collector struct {
	name string
	stat staterFunc

	acquireCountDesc         *prometheus.Desc
	acquireDurationDesc      *prometheus.Desc
	acquiredConnsDesc        *prometheus.Desc
	canceledAcquireCountDesc *prometheus.Desc
	constructingConnsDesc    *prometheus.Desc
	emptyAcquireCountDesc    *prometheus.Desc
	idleConnsDesc            *prometheus.Desc
	maxConnsDesc             *prometheus.Desc
	totalConnsDesc           *prometheus.Desc
}

// Stater is a provider of the Stat() function. Implemented by pgxpool.Pool.
type Stater interface {
	Stat() *pgxpool.Stat
}

// NewCollector creates a new Collector to collect stats from pgxpool.
func NewCollector(stater Stater, appname string) *Collector {
	fn := func() stat { return stater.Stat() }
	return newCollector(fn, appname)
}

// NewCollector is an internal only constructor for a Collecter. It accepts a
// staterFunc which provides a closure for requesting pgxpool.Stat metrics.
// Labels to each metric and may be nil. A label is recommended when an
// application uses more than one pgxpool.Pool to enable differentiation between
// them.
func newCollector(fn staterFunc, n string) *Collector {
	return &Collector{
		name: n,
		stat: fn,
		acquireCountDesc: prometheus.NewDesc(
			"pgxpool_acquire_count",
			"Cumulative count of successful acquires from the pool.",
			staticLabels, nil),
		acquireDurationDesc: prometheus.NewDesc(
			"pgxpool_acquire_duration_seconds_total",
			"Total duration of all successful acquires from the pool in nanoseconds.",
			staticLabels, nil),
		acquiredConnsDesc: prometheus.NewDesc(
			"pgxpool_acquired_conns",
			"Number of currently acquired connections in the pool.",
			staticLabels, nil),
		canceledAcquireCountDesc: prometheus.NewDesc(
			"pgxpool_canceled_acquire_count",
			"Cumulative count of acquires from the pool that were canceled by a context.",
			staticLabels, nil),
		constructingConnsDesc: prometheus.NewDesc(
			"pgxpool_constructing_conns",
			"Number of conns with construction in progress in the pool.",
			staticLabels, nil),
		emptyAcquireCountDesc: prometheus.NewDesc(
			"pgxpool_empty_acquire",
			"Cumulative count of successful acquires from the pool that waited for a resource to be released or constructed because the pool was empty.",
			staticLabels, nil),
		idleConnsDesc: prometheus.NewDesc(
			"pgxpool_idle_conns",
			"Number of currently idle conns in the pool.",
			staticLabels, nil),
		maxConnsDesc: prometheus.NewDesc(
			"pgxpool_max_conns",
			"Maximum size of the pool.",
			staticLabels, nil),
		totalConnsDesc: prometheus.NewDesc(
			"pgxpool_total_conns",
			"Total number of resources currently in the pool. The value is the sum of ConstructingConns, AcquiredConns, and IdleConns.",
			staticLabels, nil),
	}
}

var staticLabels = []string{"application_name"}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect implements the prometheus.Collector interface.
func (c *Collector) Collect(metrics chan<- prometheus.Metric) {
	s := c.stat()
	metrics <- prometheus.MustNewConstMetric(
		c.acquireCountDesc,
		prometheus.CounterValue,
		float64(s.AcquireCount()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.acquireDurationDesc,
		prometheus.CounterValue,
		s.AcquireDuration().Seconds(),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.acquiredConnsDesc,
		prometheus.GaugeValue,
		float64(s.AcquiredConns()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.canceledAcquireCountDesc,
		prometheus.CounterValue,
		float64(s.CanceledAcquireCount()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.constructingConnsDesc,
		prometheus.GaugeValue,
		float64(s.ConstructingConns()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.emptyAcquireCountDesc,
		prometheus.CounterValue,
		float64(s.EmptyAcquireCount()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.idleConnsDesc,
		prometheus.GaugeValue,
		float64(s.IdleConns()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.maxConnsDesc,
		prometheus.GaugeValue,
		float64(s.MaxConns()),
		c.name,
	)
	metrics <- prometheus.MustNewConstMetric(
		c.totalConnsDesc,
		prometheus.GaugeValue,
		float64(s.TotalConns()),
		c.name,
	)
}
