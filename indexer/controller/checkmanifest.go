package controller

import (
	"context"
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"

	"github.com/quay/claircore/indexer"
)

var scannedManifestCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "claircore",
		Subsystem: "indexer",
		Name:      "scanned_manifests",
		Help:      "Total number of scanned manifests.",
	},
	[]string{"scanned_before"},
)

func checkManifest(ctx context.Context, s *Controller) (State, error) {
	// determine if we've seen this manifest and if we've
	// scanned it with the desired scanners
	ok, err := s.Store.ManifestScanned(ctx, s.manifest.Hash, s.Vscnrs)
	if err != nil {
		return Terminal, err
	}

	scannedManifestCounter.WithLabelValues(strconv.FormatBool(ok)).Add(1)

	// if we haven't seen this manifest, determine which scanners to use, persist it
	// and transition to FetchLayer state.
	if !ok {
		zlog.Info(ctx).Msg("manifest to be scanned")

		// if a manifest was analyzed by a particular scanner we can
		// omit it from this index, as all its comprising layers were analyzed
		// by the particular scanner as well.
		filtered := make(indexer.VersionedScanners, 0, len(s.Vscnrs))
		for i := range s.Vscnrs {
			ok, err := s.Store.ManifestScanned(ctx, s.manifest.Hash, s.Vscnrs[i:i+1]) // slice this to avoid allocations
			if err != nil {
				return Terminal, err
			}
			if !ok {
				filtered = append(filtered, s.Vscnrs[i])
			}
		}
		s.Vscnrs = filtered

		err := s.Store.PersistManifest(ctx, *s.manifest)
		if err != nil {
			return Terminal, fmt.Errorf("failed to persist manifest: %w", err)
		}
		return FetchLayers, nil
	}

	// we have seen this manifest before and it's been been processed with the desired scanners
	// retrieve the existing one and transition to Terminal.
	zlog.Info(ctx).Msg("manifest already scanned")
	sr, ok, err := s.Store.IndexReport(ctx, s.manifest.Hash)
	if err != nil {
		return Terminal, fmt.Errorf("failed to retrieve manifest: %w", err)
	}
	if !ok {
		return Terminal, fmt.Errorf("failed to retrieve manifest: %w", err)
	}
	s.report = sr

	return Terminal, nil
}
