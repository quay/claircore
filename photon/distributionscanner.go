package photon

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// Photon provides one security database file per major version. So far, there are 3 versions
// Photon 1.0, Photon 2.0 and Photon 3.0

const (
	scannerName    = "photon"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

const osReleasePath = `etc/os-release`
const photonReleasePath = `etc/photon-release`

type photonRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var photonRegexes = []photonRegex{
	{
		release: Photon1,
		// regex for /etc/os-release
		regexp: regexp.MustCompile(`^.*"VMware Photon"\sVERSION="1.0"`),
	},
	{
		release: Photon2,
		// regex for /etc/os-release
		regexp: regexp.MustCompile(`^.*"VMware Photon OS"\sVERSION="2.0"`),
	},
	{
		release: Photon3,
		// regex for /etc/os-release
		regexp: regexp.MustCompile(`^.*"VMware Photon OS"\sVERSION="3.0"`),
	},
}

var _ indexer.DistributionScanner = (*DistributionScanner)(nil)
var _ indexer.VersionedScanner = (*DistributionScanner)(nil)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a photon distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated photon release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "photon/DistributionScanner.Scan").
		Str("version", ds.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	files, err := l.Files(osReleasePath, photonReleasePath)
	if err != nil {
		log.Debug().Msg("didn't find an os-release or photon-release")
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

// parse attempts to match all photon release regexp and returns the associated
// distribution if it exists.
//
// separated to it's own method to aide testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range photonRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
