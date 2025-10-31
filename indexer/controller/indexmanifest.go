package controller

import (
	"context"
	"fmt"
	"log/slog"
)

func indexManifest(ctx context.Context, c *Controller) (State, error) {
	slog.InfoContext(ctx, "starting index manifest")

	if c.report == nil {
		return Terminal, fmt.Errorf("reached IndexManifest state with a nil report field. cannot continue")
	}

	err := c.Store.IndexManifest(ctx, c.report)
	if err != nil {
		return Terminal, fmt.Errorf("indexing manifest contents failed: %w", err)
	}
	return IndexFinished, nil
}
