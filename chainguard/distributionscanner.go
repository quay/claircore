package chainguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/quay/zlog"
	"io/fs"
	"runtime/trace"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
)

const (
	scannerName    = "chainguard"
	scannerVersion = "1"
	scannerKind    = "distribution"

	chainguard = `chainguard`
	wolfi      = `wolfi`
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a chainguard or wolfi distribution.
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release
// and determine if it represents a chainguard or wolfi release.
//
// If the file is not found, or the file does not represent a chainguard nor wolfi release,
// (nil, nil) is returned.
func (s *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "chainguard/DistributionScanner.Scan",
		"version", s.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("chainguard: unable to open layer: %w", err)
	}

	b, err := fs.ReadFile(sys, osrelease.Path)
	switch {
	case errors.Is(err, nil):
		m, err := osrelease.Parse(ctx, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}

		switch id := m[`ID`]; id {
		case chainguard, wolfi:
			return []*claircore.Distribution{
				{
					Name: m[`NAME`],
					DID:  id,
					// Neither chainguard nor wolfi images are considered to be "versioned".
					// Explicitly set the version to the empty string for clarity.
					Version:    "",
					PrettyName: m[`PRETTY_NAME`],
				},
			}, nil
		default:
			// This is neither chainguard nor wolfi.
			return nil, nil
		}
	case errors.Is(err, fs.ErrNotExist):
		// os-release file must exist in chainguard and wolfi images.
		return nil, nil
	default:
		return nil, err
	}
}
