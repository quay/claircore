package java

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var searchCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "claircore_indexer",
		Subsystem: "java",
		Name:      "search_total",
		Help:      "Total number of maven search queries issued.",
	},
	[]string{"success"},
)
