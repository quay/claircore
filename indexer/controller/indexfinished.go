package controller

import (
	"context"
	"fmt"
	"log/slog"
)

// indexFinished is the terminal stateFunc. once it transitions the
// indexer to the IndexFinished state the indexer will no longer transition
// and return an IndexReport to the caller
func indexFinished(ctx context.Context, s *Controller) (State, error) {
	s.report.Success = true
	slog.InfoContext(ctx, "finishing scan")

	err := s.Store.SetIndexFinished(ctx, s.report, s.Vscnrs)
	if err != nil {
		return Terminal, fmt.Errorf("failed finish scan: %w", err)
	}

	slog.InfoContext(ctx, "manifest successfully scanned")
	return Terminal, nil
}
