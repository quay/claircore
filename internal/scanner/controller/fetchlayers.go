package controller

import (
	"context"
	"fmt"
)

func fetchLayers(ctx context.Context, s *Controller) (State, error) {
	s.logger.Info().Str("state", s.getState().String()).Msg("starting layer fetch")
	toFetch, err := reduce(ctx, s.Store, s.Vscnrs, s.manifest.Layers)
	if err != nil {
		return Terminal, fmt.Errorf("failed to determine layers to fetch: %v", err)
	}
	if len(toFetch) == 0 {
		return Terminal, fmt.Errorf("reached FetchLayer states but could not determine layers to scan")
	}
	s.logger.Debug().Str("state", s.getState().String()).Msgf("fetching %d layers", len(toFetch))
	err = s.Fetcher.Fetch(ctx, toFetch)
	if err != nil {
		s.logger.Error().Str("state", s.getState().String()).Msgf("faild to fetch layers: %v", err)
		return Terminal, fmt.Errorf("failed to fetch layers %v", err)
	}
	s.logger.Info().Str("state", s.getState().String()).Msgf("layers successfully fetched")
	return ScanLayers, nil
}
