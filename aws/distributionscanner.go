package aws

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// AWS Linux keeps a consistent os-release file between
// major releases.
// All tested images on docker hub contained os-release file

const (
	scannerName    = "aws"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

type awsRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var awsRegexes = []awsRegex{
	{
		release: Linux1,
		regexp:  regexp.MustCompile(`Amazon Linux AMI 2018.03`),
	},
	{
		release: Linux2,
		regexp:  regexp.MustCompile(`Amazon Linux 2`),
	},
}

const osReleasePath = `etc/os-release`

var _ indexer.DistributionScanner = (*DistributionScanner)(nil)
var _ indexer.VersionedScanner = (*DistributionScanner)(nil)

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
	log := zerolog.Ctx(ctx).With().
		Str("component", "aws_dist_scanner").
		Str("name", ds.Name()).
		Str("version", ds.Version()).
		Str("kind", ds.Kind()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	files, err := l.Files(osReleasePath)
	if err != nil {
		log.Debug().Msg("didn't find an os-release")
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
// separated to it's own method to aide testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range awsRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			dist := releaseToDist(ur.release)
			return dist
		}
	}
	return nil
}
