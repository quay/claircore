package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TODO(hank) Reword this metric, add more.

var scannedManifestCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "claircore",
		Subsystem: "indexer",
		Name:      "scanned_manifests",
		Help:      "Total number of scanned manifests.",
	},
	[]string{"scanned_before"},
)
