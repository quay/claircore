package rhcos

import (
	"context"
	"fmt"
	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/zlog"
	"io/fs"
	"regexp"
	"runtime/trace"
)

const (
	scannerName    = "rhcos"
	scannerVersion = "1"
	scannerKind    = "distribution"

	osReleasePath = "etc/redhat-release"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)

	issueRegexp = regexp.MustCompile(`(?P<os>Red Hat Enterprise Linux) (CoreOS release) (?P<version>[\d]+[\.]?[\d]*)`)
)

// DistributionScanner implements distribution detection logic for RHCOS.
type DistributionScanner struct{}

// Name implements [indexer.VersionedScanner].
func (*DistributionScanner) Name() string { return scannerName }

// Version implements [indexer.VersionedScanner].
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements implements [indexer.VersionedScanner].
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan implements [indexer.DistributionScanner].
//
// It looks for a redhat-release file and performs a regex match looking for the release.
// If the file is found but the regexp failed to match, an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhcos/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcos: unable to open layer: %w", err)
	}
	return scanFS(sys)
}

func scanFS(sys fs.FS) ([]*claircore.Distribution, error) {
	b, err := fs.ReadFile(sys, osReleasePath)
	if err != nil {
		return nil, err
	}
	r := issueRegexp.FindSubmatch(b)
	if len(r) != 4 {
		// found nothing
		return make([]*claircore.Distribution, 0), nil
	}
	rs := string(r[3])
	return []*claircore.Distribution{{
		Name:       "Red Hat Enterprise Linux CoreOS",
		Version:    rs,
		VersionID:  rs,
		DID:        "rhcos",
		PrettyName: "Red Hat Enterprise Linux CoreOS release " + rs,
		// CPE: cpe.MustUnbind("cpe:/o:redhat::" + s), // FIXME: CPE lookup
	}}, nil
}
