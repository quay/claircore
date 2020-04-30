package oracle

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// Oracle Linux has minor releases such as 7.7 and 6.10
// however their elsa OVAL xml sec db always references the major release
// for example: <platform>Oracle Linux 5</platform>
// for this reason the oracle distribution scanner will detect and normalize
// minor releases to major releases to match vulnerabilities correctly

const (
	scannerName    = "oracle"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

const osReleasePath = `etc/os-release`

// Oracle Linux 5 will not have os-release and only has etc/issue
const issuePath = `etc/issue`

type oracleRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var oracleRegexes = []oracleRegex{
	{
		release: Five,
		// regex for /etc/issue
		regexp: regexp.MustCompile(`(?is)Oracle Linux Server release ?5(\.\d*)?`),
	},
	{
		release: Six,
		regexp:  regexp.MustCompile(`(?is)Oracle Linux Server 6(\.\d*)?`),
	},
	{
		release: Seven,
		regexp:  regexp.MustCompile(`(?is)Oracle Linux Server 7(\.\d*)?`),
	},
	{
		release: Eight,
		regexp:  regexp.MustCompile(`(?is)Oracle Linux Server 8(\.\d*)?`),
	},
}

var _ indexer.DistributionScanner = (*DistributionScanner)(nil)
var _ indexer.VersionedScanner = (*DistributionScanner)(nil)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a Oracle distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated Oracle release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "oracle/DistributionScanner.Scan").
		Str("version", ds.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	files, err := l.Files(osReleasePath, issuePath)
	if err != nil {
		log.Debug().Msg("didn't find an os-release or issues file")
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

// parse attempts to match all Oracle release regexp and returns the associated
// distribution if it exists.
//
// separated to it's own method to aide testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range oracleRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
