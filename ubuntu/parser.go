package ubuntu

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/ovalutil"
)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ubuntu/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("ubuntu: unable to decode OVAL document: %w", err)
	}
	log.Debug().Msg("xml decoded")
	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		vs := []*claircore.Vulnerability{}
		v := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			NormalizedSeverity: normalizeSeverity(def.Advisory.Severity),
			Dist:               releaseToDist(u.release),
		}
		vs = append(vs, v)
		return vs, nil
	}
	vulns, err := ovalutil.DpkgDefsToVulns(ctx, &root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func normalizeSeverity(severity string) claircore.Severity {
	switch severity {
	case "Negligible":
		return claircore.Negligible
	case "Low":
		return claircore.Low
	case "Medium":
		return claircore.Medium
	case "High":
		return claircore.High
	case "Critical":
		return claircore.Critical
	default:
	}
	return claircore.Unknown
}
