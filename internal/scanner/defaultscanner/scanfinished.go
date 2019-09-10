package defaultscanner

import (
	"context"
	"fmt"
)

// scanFinished is the terminal stateFunc. once it transitions the
// scanner to the ScanFinished state the scanner will no longer transition
// and return a ScanReport to the caller
func scanFinished(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	s.report.Success = true
	s.logger.Info().Str("state", s.getState().String()).Msg("finishing scan")

	err := s.Store.SetScanFinished(s.report, s.vscnrs)
	if err != nil {
		s.logger.Error().Str("state", s.getState().String()).Msgf("failed to finish scan. atttempt a rescan of the manifest: %v", err)
		return Terminal, fmt.Errorf("failed finish scann. attempt a rescan of the manifest: %v", err)
	}

	s.logger.Info().Str("state", s.getState().String()).Msg("manifest successfully scanned")
	return Terminal, nil
}
