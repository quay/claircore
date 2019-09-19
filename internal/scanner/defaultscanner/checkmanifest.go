package defaultscanner

import (
	"context"
	"fmt"
)

func checkManifest(s *defaultScanner, ctx context.Context) (ScannerState, error) {
	// determine if we've seen this manifest and if we've
	// scanned it with the desired scanners
	ok, err := s.Store.ManifestScanned(ctx, s.manifest.Hash, s.vscnrs)
	if err != nil {
		s.logger.Error().Str("state", s.getState().String()).Msgf("failed to determine if manifest has been scanned: %v", err)
		return Terminal, err
	}

	// if we haven't seen this manifest enter layer scanning state
	if !ok {
		s.logger.Info().Str("state", s.getState().String()).Msg("manifest will be scanned")
		return FetchLayers, nil
	}

	// we have seen this manifest before and it's been been processed with the desired scanners
	s.logger.Info().Str("state", s.getState().String()).Msg("manifest already scanned... retreiving")
	sr, ok, err := s.Store.ScanReport(ctx, s.manifest.Hash)
	if err != nil {
		s.logger.Error().Str("state", s.getState().String()).Msgf("failed to retreieve manifest: %v", err)
		return Terminal, fmt.Errorf("failed to retrieve manifest: %v", err)
	}
	if !ok {
		s.logger.Error().Str("state", s.getState().String()).Msgf("scanner believes manifest exists but retrieve failed. further investigation is necessary")
		return Terminal, fmt.Errorf("failed to retrieve manifest: %v", err)
	}
	// set scan result to retreived.
	s.report = sr

	// return nil telling fsm to just return the s.result value to the caller
	return Terminal, nil
}
