package debian

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

const (
	scannerName    = "debian"
	scannerVersion = "v0.0.2"
	scannerKind    = "distribution"
)

type debianRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var debianRegexes = []debianRegex{
	{
		release: Bullseye,
		regexp:  regexp.MustCompile(`(?is)debian gnu/linux 11`),
	},
	{
		release: Buster,
		regexp:  regexp.MustCompile(`(?is)debian gnu/linux 10`),
	},
	{
		release: Jessie,
		regexp:  regexp.MustCompile(`(?is)debian gnu/linux 8`),
	},
	{
		release: Stretch,
		regexp:  regexp.MustCompile(`(?is)debian gnu/linux 9`),
	},
	{
		release: Wheezy,
		regexp:  regexp.MustCompile(`(?is)debian gnu/linux 7`),
	},
}

const (
	osReleasePath = `etc/os-release`
	issuePath     = `etc/issue`
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a Debian distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated Debian release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "debian/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	files, err := l.Files(osReleasePath, issuePath)
	if err != nil {
		zlog.Debug(ctx).Msg("didn't find an os-release or issue file")
		return nil, nil
	}
	for _, buff := range files {
		dist := ds.parse(buff)
		if dist != nil {
			return []*claircore.Distribution{dist}, nil
		}
	}
	return []*claircore.Distribution{}, nil
}

// parse attempts to match all Debian release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range debianRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
