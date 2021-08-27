package controller

import (
	"context"
	"fmt"

	"github.com/quay/zlog"
)

// indexFinished is the terminal stateFunc. once it transitions the
// indexer to the IndexFinished state the indexer will no longer transition
// and return an IndexReport to the caller
func indexFinished(ctx context.Context, s *Controller) (State, error) {
	s.report.Success = true
	zlog.Info(ctx).Msg("finishing scan")

	err := s.Store.SetIndexFinished(ctx, s.report, s.Vscnrs)
	if err != nil {
		return Terminal, fmt.Errorf("failed finish scan: %w", err)
	}

	zlog.Info(ctx).Msg("manifest successfully scanned")
	return Terminal, nil
}
