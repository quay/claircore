package controller

import (
	"context"
	"fmt"

	"github.com/quay/zlog"
)

func indexManifest(ctx context.Context, c *Controller) (State, error) {
	zlog.Info(ctx).Msg("starting index manifest")

	if c.report == nil {
		return Terminal, fmt.Errorf("reached IndexManifest state with a nil report field. cannot continue")
	}

	err := c.Store.IndexManifest(ctx, c.report)
	if err != nil {
		return Terminal, fmt.Errorf("indexing manifest contents failed: %w", err)
	}
	return IndexFinished, nil
}
