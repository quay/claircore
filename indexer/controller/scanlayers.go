package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/quay/claircore/indexer"
)

// scanLayers will run all scanner types against all layers if deemed necessary
// to scan
func scanLayers(ctx context.Context, c *Controller) (State, error) {
	slog.InfoContext(ctx, "layers scan start")
	defer slog.InfoContext(ctx, "layers scan done")
	err := c.LayerScanner.Scan(ctx, c.manifest.Hash, c.manifest.Layers)
	if err != nil {
		if errors.Is(err, indexer.ErrScanPartial) {
			c.partial = true
			c.report.Err = err.Error()
			slog.WarnContext(ctx, "layers scan completed with partial results", "reason", err)
			return Coalesce, nil
		}
		return Terminal, fmt.Errorf("failed to scan all layer contents: %w", err)
	}
	slog.DebugContext(ctx, "layers scan ok")
	return Coalesce, nil
}
