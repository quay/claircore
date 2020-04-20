package oracle

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

const (
	OracleLinux5Platform = "Oracle Linux 5"
	OracleLinux6Platform = "Oracle Linux 6"
	OracleLinux7Platform = "Oracle Linux 7"
	OracleLinux8Platform = "Oracle Linux 8"
)

// a mapping between oval platform string to claircore distribution
var platformToDist = map[string]*claircore.Distribution{
	OracleLinux5Platform: fiveDist,
	OracleLinux6Platform: sixDist,
	OracleLinux7Platform: sevenDist,
	OracleLinux8Platform: eightDist,
}

var _ driver.Parser = (*Updater)(nil)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "oracle/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("oracle: unable to decode OVAL document: %w", err)
	}
	log.Debug().Msg("xml decoded")
	protoVuln := func(def oval.Definition) (*claircore.Vulnerability, error) {
		// In all oracle databases tested a single
		// and correct platform string can be found inside a definition
		// search is for good measure
		var dist *claircore.Distribution
	DistSearch:
		for _, affected := range def.Affecteds {
			for _, platform := range affected.Platforms {
				if d, ok := platformToDist[platform]; ok {
					dist = d
					break DistSearch
				}
			}
		}
		if dist == nil {
			return nil, fmt.Errorf("could not determine dist")
		}
		return &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			Severity:           def.Advisory.Severity,
			NormalizedSeverity: NormalizeSeverity(def.Advisory.Severity),
			Dist:               dist,
		}, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, root, protoVuln)
	if err != nil {
		return nil, err
	}
	return vulns, err
}
