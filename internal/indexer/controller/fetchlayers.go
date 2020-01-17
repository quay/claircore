package controller

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

func fetchLayers(ctx context.Context, s *Controller) (State, error) {
	log := zerolog.Ctx(ctx).With().
		Str("state", s.getState().String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("layers fetch start")
	defer log.Info().Msg("layers fetch done")
	toFetch, err := reduce(ctx, s.Store, s.Vscnrs, s.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to determine layers to fetch: %w", err)
	}
	if len(toFetch) == 0 {
		return Terminal, fmt.Errorf("reached FetchLayer states but could not determine layers to scan")
	}
	log.Debug().
		Int("count", len(toFetch)).
		Msg("fetching layers")
	if err := s.Fetcher.Fetch(ctx, toFetch); err != nil {
		log.Warn().
			Err(err).
			Msg("layers fetch failure")
		return Terminal, fmt.Errorf("failed to fetch layers: %w", err)
	}
	log.Info().Msg("layers fetch success")
	return ScanLayers, nil
}
