package suse

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// Suse Enterprise Server has service pack releases however their security database files are bundled together
// by major version. for example `SUSE Linux Enterprise Server 15 (all Service Packs) - suse.linux.enterprise.server.15.xml`
// we choose to normalize detected distributions into major releases and parse vulnerabilities by major release versions.
//
// Suse Leap has well defined sub releases and their sec db's match up fine.

const (
	scannerName    = "suse"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

const osReleasePath = `etc/os-release`
const suseReleasePath = `etc/SuSE-release`

type suseRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var suseRegexes = []suseRegex{
	{
		release: EnterpriseServer15,
		// regex for /etc/issue
		regexp: regexp.MustCompile(`(?i)SUSE Linux Enterprise Server 15`),
	},
	{
		release: EnterpriseServer12,
		regexp:  regexp.MustCompile(`(?i)SUSE Linux Enterprise Server 12`),
	},
	{
		release: EnterpriseServer11,
		regexp:  regexp.MustCompile(`(?i)SUSE Linux Enterprise Server 11`),
	},
	{
		release: Leap151,
		regexp:  regexp.MustCompile(`(?i)openSUSE Leap 15.1`),
	},
	{
		release: Leap150,
		regexp:  regexp.MustCompile(`(?i)openSUSE Leap 15.0`),
	},
	{
		release: Leap423,
		regexp:  regexp.MustCompile(`(?i)openSUSE Leap 42.3`),
	},
}

var _ indexer.DistributionScanner = (*DistributionScanner)(nil)
var _ indexer.VersionedScanner = (*DistributionScanner)(nil)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a Suse distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated Suse release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "suse/DistributionScanner.Scan").
		Str("version", ds.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	files, err := l.Files(osReleasePath, suseReleasePath)
	if err != nil {
		log.Debug().Msg("didn't find an os-release or SuSE-release")
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

// parse attempts to match all Suse release regexp and returns the associated
// distribution if it exists.
//
// separated to it's own method to aide testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range suseRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
