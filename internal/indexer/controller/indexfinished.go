package controller

import (
	"context"
	"fmt"
)

// indexFinished is the terminal stateFunc. once it transitions the
// indexer to the IndexFinished state the indexer will no longer transition
// and return a IndexReport to the caller
func indexFinished(ctx context.Context, s *Controller) (State, error) {
	s.report.Success = true
	s.logger.Info().Str("state", s.getState().String()).Msg("finishing scan")

	err := s.Store.SetIndexFinished(ctx, s.report, s.Vscnrs)
	if err != nil {
		s.logger.Error().Str("state", s.getState().String()).Msgf("failed to finish scan. atttempt a rescan of the manifest: %v", err)
		return Terminal, fmt.Errorf("failed finish scann. attempt a rescan of the manifest: %v", err)
	}

	s.logger.Info().Str("state", s.getState().String()).Msg("manifest successfully scanned")
	return Terminal, nil
}
