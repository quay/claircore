package ubuntu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"runtime/trace"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	scannerName    = "ubuntu"
	scannerVersion = "3"
	scannerKind    = "distribution"

	osReleasePath  = `etc/os-release`
	lsbReleasePath = `etc/lsb-release`
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner implements [indexer.DistributionScanner] looking for Ubuntu distributions.
type DistributionScanner struct{}

// Name implements [scanner.VersionedScanner].
func (*DistributionScanner) Name() string { return scannerName }

// Version implements [scanner.VersionedScanner].
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements [scanner.VersionedScanner].
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan implements [indexer.DistributionScanner].
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("ubuntu: unable to open layer: %w", err)
	}
	d, err := findDist(sys)
	if err != nil {
		return nil, fmt.Errorf("ubuntu: %w", err)
	}
	if d == nil {
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDist(sys fs.FS) (*claircore.Distribution, error) {
	var err error
	var b []byte
	var idKey, verKey, nameKey string

	b, err = fs.ReadFile(sys, lsbReleasePath)
	if errors.Is(err, nil) {
		idKey = `DISTRIB_ID`
		verKey = `DISTRIB_RELEASE`
		nameKey = `DISTRIB_CODENAME`
		goto Found
	}
	b, err = fs.ReadFile(sys, osReleasePath)
	if errors.Is(err, nil) {
		idKey = `ID`
		verKey = `VERSION_ID`
		nameKey = `VERSION_CODENAME`
		goto Found
	}
	return nil, nil

Found:
	var hasID bool
	var ver, name string
	buf := bytes.NewBuffer(b)
	for l, err := buf.ReadString('\n'); len(l) != 0; l, err = buf.ReadString('\n') {
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, io.EOF):
		default:
			return nil, fmt.Errorf("unexpected error looking for %q: %w", verKey, err)
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"\r\n")
		switch k {
		case idKey:
			if !strings.EqualFold(v, "ubuntu") {
				// This is not Ubuntu, so skip it.
				return nil, nil
			}
			hasID = true
		case nameKey:
			name = v
		case verKey:
			ver = v
		}
	}
	if !hasID {
		// If ID or DISTRIB_ID is missing, just say this is not Ubuntu.
		return nil, nil
	}
	if name != "" && ver != "" {
		return mkDist(ver, name), nil
	}
	return nil, nil
}
