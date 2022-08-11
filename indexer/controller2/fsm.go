package controller

import (
	"context"
	"errors"
	"fmt"
	"runtime/trace"
	"strconv"

	"github.com/quay/zlog"

	"github.com/quay/claircore/indexer"
)

// CheckManifest determines if the manifest is novel or not.
//
// The next state is UnseenManifest or SeenManifest, depending.
func _CheckManifest(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/CheckManifest").End()
	// Determine if we've seen this manifest and if we've scanned it with the
	// desired scanners.
	seen, err := s.Store.ManifestScanned(ctx, s.Manifest.Hash, s.Indexers)
	if err != nil {
		return s.error(ctx, err)
	}
	scannedManifestCounter.WithLabelValues(strconv.FormatBool(seen)).Add(1)

	if !seen {
		return _UnseenManifest(ctx, s)
	}
	return _SeenManifest(ctx, s)
}

// UnseenManifest is entered into if the manifest is novel to the system.
//
// This step determines which indexers need to be run.
func _UnseenManifest(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/UnseenManifest").End()
	zlog.Info(ctx).Msg("manifest to be indexed")

	// If a manifest was indexed by a particular indexer, we can
	// omit it from this index becase all its comprising layers
	// were indexed by the particular indexer as well.
	filtered := make([]indexer.VersionedScanner, 0, len(s.Indexers))
	for i := range s.Indexers {
		ok, err := s.Store.ManifestScanned(ctx, s.Manifest.Hash, s.Indexers[i:i+1]) // slice this to avoid allocations
		switch {
		case !errors.Is(err, nil):
			return s.error(ctx, err)
		case !ok:
			filtered = append(filtered, s.Indexers[i])
		}
	}
	s.Indexers = filtered

	if err := s.Store.PersistManifest(ctx, *s.Manifest); err != nil { // TODO(hank) Fix this copy
		return s.error(ctx, fmt.Errorf("failed to persist manifest: %w", err))
	}
	s.Out = newIndexReport(s.Manifest.Hash)
	return _FetchLayers
}

// SeenManifest is entered into if the manifest is not novel to the system.
//
// This step reports the stored IndexReport.
func _SeenManifest(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/SeenManifest").End()
	// We have seen this manifest before and it's been been processed with the desired indexers.
	zlog.Info(ctx).Msg("manifest already indexed")
	sr, seen, err := s.Store.IndexReport(ctx, s.Manifest.Hash)
	switch {
	case !errors.Is(err, nil):
		return s.error(ctx, fmt.Errorf("failed to retrieve index report: %w", err))
	case !seen:
		return s.retry(ctx, _SeenManifest, manifestDisappeared(s.Manifest.Hash))
	}
	s.Out = sr
	return nil
}

// IndexLayers will run all scanner types against all layers if deemed necessary
// to index.
func _IndexLayers(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/IndexLayers").End()
	zlog.Info(ctx).Msg("layers index start")
	defer zlog.Info(ctx).Msg("layers index done")
	if err := s.LayerIndexer.Scan(ctx, s.Manifest.Hash, s.Manifest.Layers); err != nil {
		return s.error(ctx, fmt.Errorf("failed to index all layer contents: %w", err))
	}
	zlog.Debug(ctx).Msg("layers index ok")
	return _Coalesce
}

// IndexManifest records the results of the indexers that were run.
func _IndexManifest(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/IndexManifest").End()
	zlog.Info(ctx).Msg("starting index manifest")
	if err := s.Store.IndexManifest(ctx, s.Out); err != nil {
		return s.error(ctx, fmt.Errorf("indexing manifest contents failed: %w", err))
	}
	return _IndexFinished
}

// IndexFinished marks the IndexReport as successful and records
// is as finished.
func _IndexFinished(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/IndexFinished").End()
	s.Out.Success = true
	zlog.Info(ctx).Msg("finishing index")

	if err := s.Store.SetIndexFinished(ctx, s.Out, s.Indexers); err != nil {
		return s.error(ctx, fmt.Errorf("failed to finish index: %w", err))
	}

	zlog.Info(ctx).Msg("manifest successfully indexed")
	return nil
}
