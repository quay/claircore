package alpine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
)

// Alpine linux has patch releases but their security database
// aggregates security information by major release. We choose
// to normalize detected distributions into major.minor releases and
// parse vulnerabilities into major.minor releases

const (
	scannerName    = "alpine"
	scannerVersion = "3"
	scannerKind    = "distribution"
)

const (
	issuePath = `etc/issue`

	edgePrettyName = `Alpine Linux edge`
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)

	issueRegexp     = regexp.MustCompile(`Alpine Linux ([[:digit:]]+\.[[:digit:]]+)`)
	edgeIssueRegexp = regexp.MustCompile(`Alpine Linux [[:digit:]]+\.\w+ \(edge\)`)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a alpine distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release or issue file
// and perform a regex match for keywords indicating the associated alpine release
//
// If neither file is found a (nil, nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (s *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "alpine/DistributionScanner.Scan",
		"version", s.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("alpine: unable to open layer: %w", err)
	}
	return s.scanFs(ctx, sys)
}

func (*DistributionScanner) scanFs(ctx context.Context, sys fs.FS) (d []*claircore.Distribution, err error) {
	for _, f := range []distFunc{readOSRelease, readIssue} {
		dist, err := f(ctx, sys)
		if err != nil {
			return nil, err
		}
		if dist != nil {
			return []*claircore.Distribution{dist}, nil
		}
	}

	// Found nothing.
	return nil, nil
}

type distFunc func(context.Context, fs.FS) (*claircore.Distribution, error)

// ReadOSRelease looks for the distribution in an os-release file, if it exists.
func readOSRelease(ctx context.Context, sys fs.FS) (*claircore.Distribution, error) {
	b, err := fs.ReadFile(sys, osrelease.Path)
	switch {
	case errors.Is(err, nil):
		// parse here
		m, err := osrelease.Parse(ctx, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		if id := m[`ID`]; id != `alpine` {
			zlog.Debug(ctx).Str("id", id).Msg("seemingly not alpine")
			break
		}
		vid := m[`VERSION_ID`]
		idx := strings.LastIndexByte(vid, '.')
		if idx == -1 {
			zlog.Debug(ctx).Str("val", vid).Msg("martian VERSION_ID")
			break
		}
		v := vid[:idx]
		if m[`PRETTY_NAME`] == edgePrettyName {
			v = "edge"
		}
		return &claircore.Distribution{
			Name:    m[`NAME`],
			DID:     m[`ID`],
			Version: v,
			// BUG(hank) The current version omit the VERSION_ID data. Need to
			// investigate why. Probably because it's not in the etc/issue
			// file.
			// VersionID:  vid,
			PrettyName: m[`PRETTY_NAME`],
		}, nil
	case errors.Is(err, fs.ErrNotExist):
		zlog.Debug(ctx).
			Str("path", osrelease.Path).
			Msg("file doesn't exist")
	default:
		return nil, err
	}

	// Found nothing.
	return nil, nil
}

// ReadIssue looks for the distribution in an issue file, if it exists.
func readIssue(ctx context.Context, sys fs.FS) (*claircore.Distribution, error) {
	b, err := fs.ReadFile(sys, issuePath)
	switch {
	case errors.Is(err, nil):
		if isEdge := edgeIssueRegexp.Match(b); isEdge {
			return &claircore.Distribution{
				Name:       `Alpine Linux`,
				DID:        `alpine`,
				Version:    `edge`,
				PrettyName: edgePrettyName,
			}, nil
		}

		ms := issueRegexp.FindSubmatch(b)
		if ms == nil {
			zlog.Debug(ctx).Msg("seemingly not alpine")
			break
		}
		v := string(ms[1])
		return &claircore.Distribution{
			Name:       `Alpine Linux`,
			DID:        `alpine`,
			Version:    v,
			PrettyName: fmt.Sprintf(`Alpine Linux v%s`, v),
		}, nil
	case errors.Is(err, fs.ErrNotExist):
		zlog.Debug(ctx).
			Str("path", issuePath).
			Msg("file doesn't exist")
	default:
		return nil, err
	}

	// Found nothing.
	return nil, nil
}
