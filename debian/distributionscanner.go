package debian

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"runtime/trace"
	"strconv"
	"strings"
	"unicode"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
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
func (*DistributionScanner) Version() string { return "3" }

// Kind implements [indexer.VersionedScanner].
func (*DistributionScanner) Kind() string { return "distribution" }

// Scan implements [indexer.DistributionScanner].
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := slog.With("version", ds.Version(), "layer", l.Hash.String())
	log.DebugContext(ctx, "start")
	defer log.DebugContext(ctx, "done")

	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("debian: unable to open layer: %w", err)
	}
	d, err := findDist(ctx, log, sys)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDist(ctx context.Context, log *slog.Logger, sys fs.FS) (*claircore.Distribution, error) {
	f, err := sys.Open(osrelease.Path)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		log.DebugContext(ctx, "no os-release file")
		return nil, nil
	default:
		return nil, fmt.Errorf("debian: unexpected error: %w", err)
	}
	kv, err := osrelease.Parse(ctx, f)
	if err != nil {
		log.InfoContext(ctx, "malformed os-release file", "reason", err)
		return nil, nil
	}
	if kv[`ID`] != `debian` {
		return nil, nil
	}

	// Regex pattern matches item within string that appear as so: (bookworm), (buster), (bullseye)
	ver := regexp.MustCompile(`\(\w+\)$`)

	name, nameok := kv[`VERSION_CODENAME`]
	idstr := kv[`VERSION_ID`]
	if !nameok {
		name = strings.TrimFunc(ver.FindString(kv[`VERSION`]), func(r rune) bool { return !unicode.IsLetter(r) })
	}
	if name == "" || idstr == "" {
		log.InfoContext(ctx, "malformed os-release file", "reason", err)
		return nil, nil
	}
	id, err := strconv.ParseInt(idstr, 10, 32)
	if err != nil {
		log.InfoContext(ctx, "malformed os-release file", "reason", err)
		return nil, nil
	}
	return mkDist(name, int(id)), nil
}
