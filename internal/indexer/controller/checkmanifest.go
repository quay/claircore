package controller

import (
	"context"
	"fmt"

	"github.com/quay/claircore/internal/indexer"
	"github.com/rs/zerolog"
)

func checkManifest(ctx context.Context, s *Controller) (State, error) {
	log := zerolog.Ctx(ctx).With().
		Str("state", s.getState().String()).
		Logger()
	ctx = log.WithContext(ctx)

	// determine if we've seen this manifest and if we've
	// scanned it with the desired scanners
	ok, err := s.Store.ManifestScanned(ctx, s.manifest.Hash, s.Vscnrs)
	if err != nil {
		return Terminal, err
	}

	// if we haven't seen this manifest, determine which scanners to use, persist it
	// and transition to FetchLayer state.
	if !ok {
		log.Info().Msg("manifest to be scanned...")

		// if a manifest was analyzed by a particular scanner we can
		// omit it from this index, as all its comprising layers were analyzed
		// by the particular scanner as well.
		filtered := make(indexer.VersionedScanners, 0, len(s.Vscnrs))
		for i := range s.Vscnrs {
			ok, err := s.Store.ManifestScanned(ctx, s.manifest.Hash, s.Vscnrs[i:i+1]) // slice this to avoid allocations
			if err != nil {
				return Terminal, err
			}
			if !ok {
				filtered = append(filtered, s.Vscnrs[i])
			}
		}
		s.Vscnrs = filtered

		err := s.Store.PersistManifest(ctx, *s.manifest)
		if err != nil {
			return Terminal, fmt.Errorf("failed to persist manifest: %v", err)
		}
		return FetchLayers, nil
	}

	// we have seen this manifest before and it's been been processed with the desired scanners
	// retrieve the existing one and transition to Terminal.
	log.Info().Msg("manifest already scanned")
	sr, ok, err := s.Store.IndexReport(ctx, s.manifest.Hash)
	if err != nil {
		return Terminal, fmt.Errorf("failed to retrieve manifest: %v", err)
	}
	if !ok {
		return Terminal, fmt.Errorf("failed to retrieve manifest: %v", err)
	}
	s.report = sr

	return Terminal, nil
}
