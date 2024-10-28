package suse

import (
	"bytes"
	"context"
	"fmt"
	"runtime/trace"

	"github.com/Masterminds/semver"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
	"github.com/quay/claircore/pkg/cpe"
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

const (
	osReleasePath   = `etc/os-release`
	suseReleasePath = `etc/SuSE-release`
)

type suseType string

var (
	SLES suseType = "sles"
	LEAP suseType = "leap"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

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
	ctx = zlog.ContextWithValues(ctx,
		"component", "suse/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	files, err := l.Files(osReleasePath, suseReleasePath)
	if err != nil {
		zlog.Debug(ctx).Msg("didn't find an os-release or SuSE-release")
		return nil, nil
	}
	for _, buff := range files {
		dist := ds.parse(ctx, buff)
		if dist != nil {
			return []*claircore.Distribution{dist}, nil
		}
	}
	return []*claircore.Distribution{}, nil
}

// parse attempts to match all SUSE release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(ctx context.Context, buff *bytes.Buffer) *claircore.Distribution {
	kv, err := osrelease.Parse(ctx, buff)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("malformed os-release file")
		return nil
	}
	cpeName, cpeOK := kv["CPE_NAME"]
	if !cpeOK {
		return nil
	}
	// Instead of regexing through, we can grab the CPE.
	c, err := cpe.Unbind(cpeName)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("could not unbind CPE")
		return nil
	}

	d, err := cpeToDist(c)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("error converting cpe to distribution")
		return nil
	}

	return d
}

func cpeToDist(r cpe.WFN) (*claircore.Distribution, error) {
	if vendor, err := cpe.NewValue("opensuse"); err == nil && r.Attr[cpe.Vendor] == vendor {
		if prod, err := cpe.NewValue("leap"); err == nil && r.Attr[cpe.Product] == prod {
			return mkLeapDist(r.String(), r.Attr[cpe.Version].String()), nil
		}
	}
	if vendor, err := cpe.NewValue("suse"); err == nil && r.Attr[cpe.Vendor] == vendor {
		if prod, err := cpe.NewValue("sles"); err == nil && r.Attr[cpe.Product] == prod {
			// Canonicalize the version to the major.
			v, err := semver.NewVersion(r.Attr[cpe.Version].String())
			if err != nil {
				return nil, err
			}
			return mkELDist(r.String(), fmt.Sprint(v.Major())), nil
		}
	}
	return nil, nil
}
