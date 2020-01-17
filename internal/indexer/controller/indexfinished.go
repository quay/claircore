package controller

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

// indexFinished is the terminal stateFunc. once it transitions the
// indexer to the IndexFinished state the indexer will no longer transition
// and return a IndexReport to the caller
func indexFinished(ctx context.Context, s *Controller) (State, error) {
	log := zerolog.Ctx(ctx).With().
		Str("state", s.getState().String()).
		Logger()
	ctx = log.WithContext(ctx)
	s.report.Success = true
	log.Info().Msg("finishing scan")

	err := s.Store.SetIndexFinished(ctx, s.report, s.Vscnrs)
	if err != nil {
		return Terminal, fmt.Errorf("failed finish scann. attempt a rescan of the manifest: %v", err)
	}

	log.Info().Msg("manifest successfully scanned")
	return Terminal, nil
}
