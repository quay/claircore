package rhel

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/pkg/ovalutil"
)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("rhel: unable to decode OVAL document: %w", err)
	}
	log.Debug().Msg("xml decoded")
	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		vs := []*claircore.Vulnerability{}
		for _, affected := range def.Advisory.AffectedCPEList {
			// Work around having empty entries. This seems to be some issue
			// with the tool used to produce the database but only seems to
			// appear sometimes, like RHSA-2018:3140 in the rhel-7-alt database.
			if affected == "" {
				continue
			}

			wfn, err := cpe.Unbind(affected)
			if err != nil {
				return nil, err
			}
			v := &claircore.Vulnerability{
				Updater:            u.Name(),
				Name:               def.Title,
				Description:        def.Description,
				Issued:             def.Advisory.Issued.Date,
				Links:              ovalutil.Links(def),
				Severity:           def.Advisory.Severity,
				NormalizedSeverity: NormalizeSeverity(def.Advisory.Severity),
				Repo: &claircore.Repository{
					Name: affected,
					CPE:  wfn,
					Key:  RedHatRepositoryKey,
				},
				// each updater is configured to parse a rhel release
				// specific xml database. we'll use the updater's release
				// to map the parsed vulnerabilities
				Dist: releaseToDist(u.release),
			}
			vs = append(vs, v)
		}
		return vs, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}
