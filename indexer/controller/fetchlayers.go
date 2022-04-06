package controller

import (
	"context"
	"fmt"

	"github.com/quay/zlog"
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
	zlog.Info(ctx).Msg("layers fetch success")
	return ScanLayers, nil
}
