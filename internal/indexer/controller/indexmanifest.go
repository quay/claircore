package controller

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

func indexManifest(ctx context.Context, c *Controller) (State, error) {
	log := zerolog.Ctx(ctx).With().
		Str("state", c.getState().String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting to index manifest...")

	if c.report == nil {
		return Terminal, fmt.Errorf("reached IndexManifest state with a nil report field. cannot continue")
	}

	err := c.Store.IndexManifest(ctx, c.report)
	if err != nil {
		return Terminal, fmt.Errorf("indexing manifest contents failed: %v", err)
	}
	return IndexFinished, nil
}
