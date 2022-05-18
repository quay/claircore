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
	"github.com/quay/claircore/pkg/tarfs"
)

const (
	osReleasePath = `etc/os-release`
	rhReleasePath = `etc/redhat-release`
)

const (
	scannerName    = "rhel"
	scannerVersion = "2"
	scannerKind    = "distribution"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)

	releaseRegexp = regexp.MustCompile(`Red Hat Enterprise Linux (?:Server)?\s*(?:release)?\s*(\d+)(?:\.\d)?`)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a RHEL distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or redhat-release file
// and perform a regex match for keywords indicating the associated RHEL release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	rd, err := l.Reader()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to create layer reader: %w", err)
	}
	defer rd.Close()
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open tarfs: %w", err)
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
