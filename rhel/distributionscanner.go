package rhel

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

const osReleasePath = `etc/os-release`
const rhReleasePath = `etc/redhat-release`

const (
	scannerName    = "rhel"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

type rhelRegex struct {
	release Release
	regexp  *regexp.Regexp
}

// the follow set of regexps will match both the PrettyName in the os-releaes file
// ex: Red Hat Enterprise Linux Server 7.7 (Maipo)
// and the release string in the redhat-release
// ex: Red Hat Enterprise Linux Server release 7.7 (Maipo)
var rhelRegexes = []rhelRegex{
	{
		release: RHEL3,
		// regex for /etc/issue
		regexp: regexp.MustCompile(`Red Hat Enterprise Linux (Server)?\s*(release)?\s*3(\.\d)?`),
	},
	{
		release: RHEL4,
		regexp:  regexp.MustCompile(`Red Hat Enterprise Linux (Server)?\s*(release)?\s*4(\.\d)?`),
	},
	{
		release: RHEL5,
		regexp:  regexp.MustCompile(`Red Hat Enterprise Linux (Server)?\s*(release)?\s*5(\.\d)?`),
	},
	{
		release: RHEL6,
		regexp:  regexp.MustCompile(`Red Hat Enterprise Linux (Server)?\s*(release)?\s*6(\.\d)?`),
	},
	{
		release: RHEL7,
		regexp:  regexp.MustCompile(`Red Hat Enterprise Linux (Server)?\s*(release)?\s*7(\.\d)?`),
	},
	{
		release: RHEL8,
		regexp:  regexp.MustCompile(`Red Hat Enterprise Linux (Server)?\s*(release)?\s*8(\.\d)?`),
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
		Str("component", "rhel/DistributionScanner.Scan").
		Str("version", ds.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	files, err := l.Files(osReleasePath, rhReleasePath)
	if err != nil {
		log.Debug().Msg("didn't find an os-release or redhat-release file")
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
	for _, ur := range rhelRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
