package debian

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime/trace"
	"strconv"
	"strings"
	"unicode"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
	"github.com/quay/claircore/pkg/tarfs"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a Debian distribution.
type DistributionScanner struct{}

// Name implements [indexer.VersionedScanner].
func (*DistributionScanner) Name() string { return "debian" }

// Version implements [indexer.VersionedScanner].
func (*DistributionScanner) Version() string { return "2" }

// Kind implements [indexer.VersionedScanner].
func (*DistributionScanner) Kind() string { return "distribution" }

// Scan implements [indexer.DistributionScanner].
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "debian/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	rd, err := l.Reader()
	if err != nil {
		return nil, fmt.Errorf("debian: unable to open layer: %w", err)
	}
	defer rd.Close()
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, fmt.Errorf("debian: unable to open layer: %w", err)
	}
	d, err := findDist(ctx, sys)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDist(ctx context.Context, sys fs.FS) (*claircore.Distribution, error) {
	f, err := sys.Open(osrelease.Path)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		zlog.Debug(ctx).Msg("no os-release file")
		return nil, nil
	default:
		return nil, fmt.Errorf("debian: unexpected error: %w", err)
	}
	kv, err := osrelease.Parse(ctx, f)
	if err != nil {
		zlog.Info(ctx).
			Err(err).Msg("malformed os-release file")
		return nil, nil
	}
	if kv[`ID`] != `debian` {
		return nil, nil
	}

	name, nameok := kv[`VERSION_CODENAME`]
	idstr := kv[`VERSION_ID`]
	if !nameok {
		name = strings.TrimFunc(kv[`VERSION`], func(r rune) bool { return !unicode.IsLetter(r) })
	}
	if name == "" || idstr == "" {
		zlog.Info(ctx).
			Err(err).Msg("malformed os-release file")
		return nil, nil
	}
	id, err := strconv.ParseInt(idstr, 10, 32)
	if err != nil {
		zlog.Info(ctx).
			Err(err).Msg("malformed os-release file")
		return nil, nil
	}
	return mkDist(name, int(id)), nil
}
