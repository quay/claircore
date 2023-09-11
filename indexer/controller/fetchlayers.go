package controller

import (
	"context"
	"fmt"

	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/wart"
)

func fetchLayers(ctx context.Context, s *Controller) (State, error) {
	zlog.Info(ctx).Msg("layers fetch start")
	defer zlog.Info(ctx).Msg("layers fetch done")
	toFetch, err := reduce(ctx, s.Store, s.Vscnrs, s.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to determine layers to fetch: %w", err)
	}
	zlog.Debug(ctx).
		Int("count", len(toFetch)).
		Msg("fetching layers")
	if err := s.Realizer.Realize(ctx, toFetch); err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("layers fetch failure")
		return Terminal, fmt.Errorf("failed to fetch layers: %w", err)
	}
	// With the addition of the LayerDescription abstraction, it's possible that
	// the "toFetch" slice is modified by the Realize call above. Once the
	// LayerDescription type is plumbed through the Indexer, this can be
	// removed.
	wart.CopyLayerPointers(s.manifest.Layers, toFetch)
	zlog.Info(ctx).Msg("layers fetch success")
	return ScanLayers, nil
}
