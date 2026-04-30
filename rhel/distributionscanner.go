package rhel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"runtime/trace"
	"strconv"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)

	releaseRegexp = regexp.MustCompile(`Red Hat Enterprise Linux (?:Server|Atomic Host)?\s*(?:release)?\s*(\d+)(?:\.\d)?`)
)

// DistributionScanner implements distribution detection logic for RHEL using os-release
// files (`etc/os-release`, then `usr/lib/os-release` if the former is absent).
//
// The DistributionScanner can be used concurrently.
type DistributionScanner struct{}

// Name implements [indexer.VersionedScanner].
func (*DistributionScanner) Name() string { return "rhel" }

// Version implements [indexer.VersionedScanner].
func (*DistributionScanner) Version() string { return "3" }

// Kind implements [indexer.VersionedScanner].
func (*DistributionScanner) Kind() string { return "distribution" }

// Scan implements [indexer.DistributionScanner].
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}
	d, err := findDistribution(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
	}
	if d == nil {
		slog.DebugContext(ctx, "didn't find an os-release file")
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDistribution(ctx context.Context, sys fs.FS) (*claircore.Distribution, error) {
	for _, p := range []string{osrelease.Path, osrelease.FallbackPath} {
		b, err := fs.ReadFile(sys, p)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
		}
		if ms := releaseRegexp.FindSubmatch(b); ms != nil {
			num, err := strconv.ParseInt(string(ms[1]), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
			}
			return mkRelease(num), nil
		}
		m, err := osrelease.Parse(ctx, bytes.NewReader(b))
		if err != nil {
			continue
		}
		if m["ID"] == "hummingbird" {
			d := &claircore.Distribution{
				Name:       m["NAME"],
				DID:        m["ID"],
				VersionID:  m["VERSION_ID"],
				Version:    m["VERSION"],
				PrettyName: m["PRETTY_NAME"],
			}
			if s := m["CPE_NAME"]; s != "" {
				if wfn, err := cpe.Unbind(s); err == nil {
					d.CPE = wfn
				}
			}
			return d, nil
		}
	}
	return nil, nil
}
