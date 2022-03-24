package rhel

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
	osReleasePath = `etc/os-release`
	rhReleasePath = `etc/redhat-release`
)

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

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a RHEL distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or redhat-release file
// and perform a regex match for keywords indicating the associated RHEL release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	files, err := l.Files(osReleasePath, rhReleasePath)
	if err != nil {
		zlog.Debug(ctx).Msg("didn't find an os-release or redhat-release file")
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

// parse attempts to match all RHEL release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range rhelRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return releaseToDist(ur.release)
		}
	}
	return nil
}
