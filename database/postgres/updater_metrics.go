package postgres

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	updateEnrichmentsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "postgres/Updater",
			Name:      "updateenrichments_total",
			Help:      "Total number of database queries issued in the UpdateEnrichments method",
		},
		[]string{"query", "error"},
	)
	updateEnrichmentsAffected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "postgres/Updater",
			Name:      "updateenrichments_affected_total",
			Help:      "Total number of rows affected in the UpdateEnrichments method",
		},
		[]string{"query", "error"},
	)
	updateEnrichmentsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "postgres/Updater",
			Name:      "updateenrichments_duration_seconds",
			Help:      "Duration of queries issued in the UpdateEnrichments method",
		},
		[]string{"query", "error"},
	)

	updateVulnerabilitiesCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "postgres/Updater",
			Name:      "updatevulnerabilities_total",
			Help:      "Total number of database queries issued in the UpdateVulnerabilities method",
		},
		[]string{"query", "error"},
	)
	updateVulnerabilitiesAffected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "claircore",
			Subsystem: "postgres/Updater",
			Name:      "updatevulnerabilities_affected_total",
			Help:      "Total number of rows affected in the UpdateVulnerabilities method",
		},
		[]string{"query", "error"},
	)
	updateVulnerabilitiesDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "claircore",
			Subsystem: "postgres/Updater",
			Name:      "updatevulnerabilities_duration_seconds",
			Help:      "Duration of queries issued in the UpdateVulnerabilities method",
		},
		[]string{"query", "error"},
	)
)
