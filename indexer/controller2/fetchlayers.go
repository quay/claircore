package controller

import (
	"context"
	"errors"
	"fmt"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// FetchLayers is the step that makes sure needed Layers are available
// locally.
func _FetchLayers(ctx context.Context, s *indexState) stateFn {
	defer trace.StartRegion(ctx, "indexer/controller/FetchLayers").End()
	zlog.Info(ctx).Msg("layers fetch start")
	defer zlog.Info(ctx).Msg("layers fetch done")
	toFetch, err := reduce(ctx, s.Store, s.Indexers, s.Manifest.Layers)
	if err != nil {
		return s.error(ctx, fmt.Errorf("failed to determine layers to fetch: %w", err))
	}
	zlog.Debug(ctx).
		Int("count", len(toFetch)).
		Msg("fetching layers")
	if err := s.Realizer.Realize(ctx, toFetch); err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("layers fetch failure")
		return s.error(ctx, fmt.Errorf("failed to fetch layers: %w", err))
	}
	zlog.Info(ctx).Msg("layers fetch success")
	return _IndexLayers
}

// Reduce filters out layers that do not need to be fetched and indexed.
func reduce(ctx context.Context, store indexer.Store, vs []indexer.VersionedScanner, ls []*claircore.Layer) ([]*claircore.Layer, error) {
	do := make([]*claircore.Layer, 0, len(ls))
Layer:
	for _, l := range ls {
		for _, v := range vs {
			ok, err := store.LayerScanned(ctx, l.Hash, v)
			switch {
			case !errors.Is(err, nil):
				zlog.Debug(ctx).
					Stringer("layer", l.Hash).
					Err(err).
					Msg("unable to lookup layer")
				return nil, err
			case !ok:
				do = append(do, l)
				continue Layer
			}
		}
	}
	return do, nil
}
