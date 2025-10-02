package controller

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/quay/claircore/internal/wart"
)

func fetchLayers(ctx context.Context, s *Controller) (State, error) {
	slog.InfoContext(ctx, "layers fetch start")
	defer slog.InfoContext(ctx, "layers fetch done")
	toFetch, err := reduce(ctx, s.Store, s.Vscnrs, s.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to determine layers to fetch: %w", err)
	}
	slog.DebugContext(ctx, "fetching layers", "count", len(toFetch))
	if err := s.Realizer.Realize(ctx, toFetch); err != nil {
		slog.WarnContext(ctx, "layers fetch failure", "reason", err)
		return Terminal, fmt.Errorf("failed to fetch layers: %w", err)
	}
	// With the addition of the LayerDescription abstraction, it's possible that
	// the "toFetch" slice is modified by the Realize call above. Once the
	// LayerDescription type is plumbed through the Indexer, this can be
	// removed.
	wart.CopyLayerPointers(s.manifest.Layers, toFetch)
	slog.InfoContext(ctx, "layers fetch success")
	return ScanLayers, nil
}
