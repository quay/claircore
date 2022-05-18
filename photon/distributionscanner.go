package photon

import (
	"bytes"
	"context"
	"regexp"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// Photon provides one security database file per major version. So far, there are 3 versions
// Photon 1.0, Photon 2.0 and Photon 3.0

const (
	scannerName    = "photon"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

const (
	osReleasePath     = `etc/os-release`
	photonReleasePath = `etc/photon-release`
)

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

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

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
	ctx = zlog.ContextWithValues(ctx,
		"component", "photon/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	files, err := l.Files(osReleasePath, photonReleasePath)
	if err != nil {
		zlog.Debug(ctx).Msg("didn't find an os-release or photon-release")
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

// parse attempts to match all Photon release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range photonRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
