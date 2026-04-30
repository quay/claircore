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

// DistributionScanner implements distribution detection logic for RHEL by looking for
// an `etc/os-release` file in the layer and failing that, an `etc/redhat-release` file.
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
		slog.DebugContext(ctx, "didn't find an os-release or redhat-release file")
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDistribution(ctx context.Context, sys fs.FS) (*claircore.Distribution, error) {
	// TODO(ross): It is not ideal to special-case Oracle Linux like this here.
	// Ideally, each distribution scanner does it own work and does not know about the existence
	// of other distribution scanners.
	// It would be great to solely use etc/os-release; however, ClairCore still supports
	// RHEL 6 which does not ship with etc/os-release, so this function must continue to rely on
	// etc/redhat-release.
	// Oracle Linux ships with etc/oracle-release as well as an unmodified etc/redhat-release, which means
	// this function may accidentally claim the distribution is RHEL when it is actually Oracle Linux.
	// For example: Oracle Linux 9 (as of writing) contains the following contents in the etc/redhat-release file:
	// Red Hat Enterprise Linux release 9.3 (Plow)
	// For now, special case Oracle Linux until RHEL 6 support is dropped.
	const oracleReleasePath = `etc/oracle-release`
	_, err := fs.Stat(sys, oracleReleasePath)
	switch {
	case errors.Is(err, nil):
		// The etc/oracle-release file exists, so this is an Oracle Linux distribution,
		// and not RHEL.
		return nil, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
	default:
		// OK.
	}

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
		if ms := releaseRegexp.FindSubmatch(b); ms != nil {
			num, err := strconv.ParseInt(string(ms[1]), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("rhel: unexpected error reading files: %w", err)
			}
			return mkRelease(num), nil
		}
		if n != osReleasePath {
			continue
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
