package rhel

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

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)

	releaseRegexp = regexp.MustCompile(`Red Hat Enterprise Linux (?:Server)?\s*(?:release)?\s*(\d+)(?:\.\d)?`)
)

// DistributionScanner implements distribution detection logic for RHEL by looking for
// an `etc/os-release` file in the layer and failing that, an `etc/redhat-release` file.
//
// The DistributionScanner can be used concurrently.
type DistributionScanner struct{}

// Name implements [indexer.VersionedScanner].
func (*DistributionScanner) Name() string { return "rhel" }

// Version implements [indexer.VersionedScanner].
func (*DistributionScanner) Version() string { return "2" }

// Kind implements [indexer.VersionedScanner].
func (*DistributionScanner) Kind() string { return "distribution" }

// Scan implements [indexer.DistributionScanner].
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}
	d, err := findDistribution(sys)
	if err != nil {
		return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
	}
	if d == nil {
		zlog.Debug(ctx).Msg("didn't find an os-release or redhat-release file")
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDistribution(sys fs.FS) (*claircore.Distribution, error) {
	const (
		osReleasePath = `etc/os-release`
		rhReleasePath = `etc/redhat-release`
	)
	for _, n := range []string{rhReleasePath, osReleasePath} {
		b, err := fs.ReadFile(sys, n)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
		}
		ms := releaseRegexp.FindSubmatch(b)
		if ms == nil {
			continue
		}
		num, err := strconv.ParseInt(string(ms[1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
		}
		return mkRelease(num), nil
	}
	return nil, nil
}
