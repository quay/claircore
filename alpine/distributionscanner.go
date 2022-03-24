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
	"github.com/quay/claircore/pkg/tarfs"
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
		dist:   alpine3_16Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.16`),
	},
	{
		dist:   alpine3_15Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.15`),
	},
	{
		dist:   alpine3_14Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.14`),
	},
	{
		dist:   alpine3_13Dist,
		regexp: regexp.MustCompile(`Alpine Linux v?3\.13`),
	},
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

const (
	osReleasePath = `etc/os-release`
	issuePath     = `etc/issue`
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
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

// Scan will inspect the layer for an os-release or lsb-release file
// and perform a regex match for keywords indicating the associated alpine release
//
// If neither file is found a (nil, nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "alpine/DistributionScanner.Scan",
		"version", ds.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	rc, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	sys, err := tarfs.New(rc)
	if err != nil {
		return nil, err
	}
	return ds.scanFs(ctx, sys)
}

func (s *DistributionScanner) scanFs(ctx context.Context, sys fs.FS) (d []*claircore.Distribution, err error) {
	// Use weirdo goto construction to pick the first instance.
	var b []byte

	// Look for an os-release file.
	b, err = fs.ReadFile(sys, osrelease.Path)
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
		d = append(d, &claircore.Distribution{
			Name:    m[`NAME`],
			DID:     m[`ID`],
			Version: v,
			// BUG(hank) The current version omit the VERSION_ID data. Need to
			// investigate why. Probably because it's not in the etc/issue
			// file.
			// VersionID:  vid,
			PrettyName: m[`PRETTY_NAME`],
		})
		goto Done
	case errors.Is(err, fs.ErrNotExist):
		zlog.Debug(ctx).
			Str("path", osrelease.Path).
			Msg("file doesn't exist")
	default:
		return nil, err
	}
	// Look for the issue file.
	b, err = fs.ReadFile(sys, issuePath)
	switch {
	case errors.Is(err, nil):
		// parse here
		ms := issueRegexp.FindSubmatch(b)
		if ms == nil {
			zlog.Debug(ctx).Msg("seemingly not alpine")
			break
		}
		v := string(ms[1])
		d = append(d, &claircore.Distribution{
			Name:       `Alpine Linux`,
			DID:        `alpine`,
			Version:    v,
			PrettyName: fmt.Sprintf(`Alpine Linux v%s`, v),
		})
		goto Done
	case errors.Is(err, fs.ErrNotExist):
		zlog.Debug(ctx).
			Str("path", issuePath).
			Msg("file doesn't exist")
	default:
		return nil, err
	}
	// Found nothing.
	return nil, nil

Done:
	return d, nil
}

var issueRegexp = regexp.MustCompile(`Alpine Linux ([[:digit:]]+\.[[:digit:]]+)`)

// parse attempts to match all Alpine release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) *claircore.Distribution {
	for _, ur := range alpineRegexes {
		if ur.regexp.Match(buff.Bytes()) {
			return ur.dist
		}
	}
	return nil
}
