package alpine

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// Alpine linux has patch releases but their security database
// aggregates security information by major release. We choose
// to normalize detected distributions into major.minor releases and
// parse vulnerabilities into major.minor releases

const (
	scannerName    = "alpine"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

type alpineRegex struct {
	dist   *claircore.Distribution
	regexp *regexp.Regexp
}

// the following regexps will match the PrettyName in the os-release file
// ex: "Alpine Linux v3.3"
// and the issue string in the issue file
// ex: "Welcome to Alpine Linux 3.3"
var alpineRegexes = []alpineRegex{
	{
		dist:   alpine3_12Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.12`),
	},
	{
		dist:   alpine3_11Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.11`),
	},
	{
		dist:   alpine3_10Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.10`),
	},
	{
		dist:   alpine3_9Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.9`),
	},
	{
		dist:   alpine3_8Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.8`),
	},
	{
		dist:   alpine3_7Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.7`),
	},
	{
		dist:   alpine3_6Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.6`),
	},
	{
		dist:   alpine3_5Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.5`),
	},
	{
		dist:   alpine3_4Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.4`),
	},
	{
		dist:   alpine3_3Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.3`),
	},
}

const osReleasePath = `etc/os-release`
const issuePath = `etc/issue`

var _ indexer.DistributionScanner = (*DistributionScanner)(nil)
var _ indexer.VersionedScanner = (*DistributionScanner)(nil)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a alpine distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated alpine release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "alpine/DistributionScanner.Scan").
		Str("version", ds.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	files, err := l.Files(osReleasePath, issuePath)
	if err != nil {
		log.Debug().Msg("didn't find an os-release or issue file")
		return nil, nil
	}
	// Always check the os-release file first.
	if b, ok := files[osReleasePath]; ok {
		dist := ds.parse(b)
		if dist != nil {
			return []*claircore.Distribution{dist}, nil
		}
	}
	if b, ok := files[issuePath]; ok {
		dist := ds.parse(b)
		if dist != nil {
			return []*claircore.Distribution{dist}, nil
		}
	}
	return []*claircore.Distribution{}, nil
}

// parse attempts to match all alpine release regexp and returns the associated
// distribution if it exists.
//
// separated to it's own method to aide testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range alpineRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return ur.dist
		}
	}
	return nil
}
