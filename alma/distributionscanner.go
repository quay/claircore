package alma

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"runtime/trace"
	"strconv"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	scannerName    = "alma"
	scannerVersion = "1"
	scannerKind    = "distribution"
)

var cpeRegexp = regexp.MustCompile(`CPE_NAME="cpe:/o:almalinux:almalinux:(\d+)::baseos"`)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of an alma distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "alma/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("alma: unable to open layer: %w", err)
	}
	d, err := findDistribution(sys)
	if err != nil {
		return nil, fmt.Errorf("alma: unexpected error reading files: %w", err)
	}
	if d == nil {
		zlog.Debug(ctx).Msg("didn't find etc/os-release")
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDistribution(sys fs.FS) (*claircore.Distribution, error) {
	const osReleasePath = `etc/os-release`
	b, err := fs.ReadFile(sys, osReleasePath)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		return nil, fmt.Errorf("alma: unexpected error reading os-release file: %w", err)
	}
	ms := cpeRegexp.FindSubmatch(b)
	if ms == nil {
		return nil, nil
	}
	if len(ms) != 2 {
		return nil, fmt.Errorf("alma: malformed os-release file: %q", b)
	}
	_, err = strconv.Atoi(string(ms[1]))
	if err != nil {
		return nil, fmt.Errorf("alma: unexpected error reading os-releasefile: %w", err)
	}
	return mkRelease(string(ms[1])), nil
}
