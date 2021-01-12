package controller

import (
	"context"
	"fmt"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
)

func fetchLayers(ctx context.Context, s *Controller) (State, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("state", s.getState().String()))
	zlog.Info(ctx).Msg("layers fetch start")
	defer zlog.Info(ctx).Msg("layers fetch done")
	toFetch, err := reduce(ctx, s.Store, s.Vscnrs, s.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to determine layers to fetch: %w", err)
	}
	zlog.Debug(ctx).
		Int("count", len(toFetch)).
		Msg("fetching layers")
	if err := s.Fetcher.Fetch(ctx, toFetch); err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("layers fetch failure")
		return Terminal, fmt.Errorf("failed to fetch layers: %w", err)
	}
	zlog.Info(ctx).Msg("layers fetch success")
	return ScanLayers, nil
}
