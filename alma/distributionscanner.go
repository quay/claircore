package alma

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/cpe"
)

const osReleasePath = `etc/os-release`

const (
	scannerName    = "alma"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

type Release int

type almaRegex struct {
	release Release
	regexp  *regexp.Regexp
}

var _ indexer.DistributionScanner = (*DistributionScanner)(nil)
var _ indexer.VersionedScanner = (*DistributionScanner)(nil)

// DistributionScanner attempts to discover if a layer
// displays characteristics of a Almalinux distribution
type DistributionScanner struct{}

// Name implements scanner.VersionedScanner.
func (*DistributionScanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*DistributionScanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*DistributionScanner) Kind() string { return scannerKind }

// Scan will inspect the layer for an os-release file and perform
// a regex match for keywords indicating the associated Almalinux release
//
// If neither file is found a (nil,nil) is returned.
// If the files are found but all regexp fail to match an empty slice is returned.
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "almalinux/DistributionScanner.Scan"),
		label.String("version", ds.Version()),
		label.String("layer", l.Hash.String()))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")
	files, err := l.Files(osReleasePath)
	if err != nil {
		zlog.Debug(ctx).Msg("didn't find an os-release file")
		return nil, nil
	}
	for _, buff := range files {
		dist, err := ds.parse(buff)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("unable to parse os-release file")
		}
		if dist != nil {
			return []*claircore.Distribution{dist}, nil
		}
	}
	return []*claircore.Distribution{}, nil
}

// parse attempts to match all Almalinux release regexp and returns the associated
// distribution if it exists.
//
// separated into its own method to aid testing.
func (ds *DistributionScanner) parse(buff *bytes.Buffer) (*claircore.Distribution, error) {
	osReleaseKV, err := parseOSRelease(buff)
	if err != nil {
		return nil, err
	}
	if name, ok := osReleaseKV["NAME"]; !ok || name != "AlmaLinux" {
		return nil, nil
	}

	dist := &claircore.Distribution{}

	if verID, ok := osReleaseKV["VERSION_ID"]; ok {
		// We're only bothered about major versions
		verParts := strings.Split(verID, ".")
		if len(verParts) > 0 {
			dist.ID = verParts[0]
		}
	}
	dist.DID = osReleaseKV["ID"]
	dist.Name = osReleaseKV["NAME"]
	dist.Version = osReleaseKV["VERSION"]
	dist.VersionID = osReleaseKV["VERSION_ID"]
	// TODO (crozzy): VersionCodeName?
	// TODO (crozzy): Arch?
	cpe, err := cpe.Unbind(osReleaseKV["CPE_NAME"])
	if err != nil {
		return nil, err // not sure, log and carry on, log and return?
	}
	dist.CPE = cpe
	dist.PrettyName = osReleaseKV["PRETTY_NAME"]

	return dist, nil
}

func parseOSRelease(buff *bytes.Buffer) (map[string]string, error) {
	res := make(map[string]string)
	scanner := bufio.NewScanner(buff)
	for scanner.Scan() {
		b := bytes.TrimSpace(scanner.Bytes())
		ls := bytes.SplitN(b, []byte("="), 2)
		if len(ls) != 2 {
			continue
		}
		key, value := ls[0], ls[1]
		if value[0] == byte('"') && value[len(value)-1] == byte('"') {
			value = value[1 : len(value)-1]
		}
		res[string(key)] = string(value)
	}

	if err := scanner.Err(); err != nil {
		return res, err
	}
	return res, nil
}
