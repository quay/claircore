package aws

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// AWS Linux keeps a consistent os-release file between
// major releases.
// All tested images on docker hub contained os-release file
//
// ScannerVersion increased to 2 when adding AL2023

const (
	scannerName    = "aws"
	scannerVersion = "2"
	scannerKind    = "distribution"
)

type awsRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var awsRegexes = []awsRegex{
	{
		release: Linux1,
		regexp:  regexp.MustCompile(`CPE_NAME="cpe:/o:amazon:linux:201.\.0[39]:ga"`),
	},
	{
		release: Linux2,
		regexp:  regexp.MustCompile(`CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2"`),
	},
	{
		release: Linux2023,
		regexp:  regexp.MustCompile(`CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"`),
	},
}

const osReleasePath = `etc/os-release`

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a AWS distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated AWS release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "aws_dist_scanner",
		"name", ds.Name(),
		"version", ds.Version(),
		"kind", ds.Kind(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	files, err := l.Files(osReleasePath)
	if err != nil {
		zlog.Debug(ctx).Msg("didn't find an os-release")
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

// parse attempts to match all AWS release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range awsRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			dist := releaseToDist(ur.release)
			return dist
		}
	}
	return nil
}
