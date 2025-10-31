package controller

import (
	"context"
	"fmt"
	"log/slog"
)

// scanLayers will run all scanner types against all layers if deemed necessary
// to scan
func scanLayers(ctx context.Context, c *Controller) (State, error) {
	slog.InfoContext(ctx, "layers scan start")
	defer slog.InfoContext(ctx, "layers scan done")
	err := c.LayerScanner.Scan(ctx, c.manifest.Hash, c.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to scan all layer contents: %w", err)
	}
	slog.DebugContext(ctx, "layers scan ok")
	return Coalesce, nil
}
