package controller

import (
	"context"
	"fmt"

	"github.com/quay/zlog"
)

// scanLayers will run all scanner types against all layers if deemed necessary
// to scan
func scanLayers(ctx context.Context, c *Controller) (State, error) {
	zlog.Info(ctx).Msg("layers scan start")
	defer zlog.Info(ctx).Msg("layers scan done")
	err := c.LayerScanner.Scan(ctx, c.manifest.Hash, c.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to scan all layer contents: %w", err)
	}
	zlog.Debug(ctx).Msg("layers scan ok")
	return Coalesce, nil
}
