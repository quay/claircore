package rhel

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/claircore/rhel/internal/common"
)

// Parse implements [driver.Updater].
//
// Parse treats the data inside the provided io.ReadCloser as Red Hat
// flavored OVAL XML. The distribution associated with vulnerabilities
// is configured via the Updater. The repository associated with
// vulnerabilies is based on the affected CPE list.
func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("rhel: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")
	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		vs := []*claircore.Vulnerability{}

		defType, err := ovalutil.GetDefinitionType(def)
		if err != nil {
			return nil, err
		}
		// Red Hat OVAL data include information about vulnerabilities,
		// that actually don't affect the package in any way. Storing them
		// would increase number of records in DB without adding any value.
		if isSkippableDefinitionType(defType) {
			return vs, nil
		}

		// Set the severity to the calculated CVSS score,
		// if it exists. Otherwise, set it to the given severity.
		severity := cvss(ctx, def)
		if severity == "" {
			severity = def.Advisory.Severity
		}

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
				Severity:           severity,
				NormalizedSeverity: common.NormalizeSeverity(def.Advisory.Severity),
				Repo: &claircore.Repository{
					Name: affected,
					CPE:  wfn,
					Key:  repositoryKey,
				},
				Dist: u.dist,
			}
			vs = append(vs, v)
		}
		return vs, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, &root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func isSkippableDefinitionType(defType ovalutil.DefinitionType) bool {
	// TODO: Delete CVEDefinition of the condition when all work related
	// to new OVAL data is done.
	return defType == ovalutil.UnaffectedDefinition ||
		defType == ovalutil.NoneDefinition ||
		defType == ovalutil.CVEDefinition
}

// CVSS returns the CVSS score + vector for the given vulnerability definition
// in the form of score/vector.
//
// For advisories, the CVSS score is the maximum of all the related CVEs' scores,
// with a preference for CVSSv3.
func cvss(ctx context.Context, def oval.Definition) string {
	var cvss3, cvss2 struct {
		score  float64
		vector string
	}

	// For CVEs, there will only be 1 item in this slice.
	// For RHSAs, RHBAs, etc, there will typically be 1 or more.
	for _, cve := range def.Advisory.Cves {
		if cve.Cvss3 != "" {
			score, vector, found := strings.Cut(cve.Cvss3, "/")
			if !found {
				zlog.Warn(ctx).
					Str("CVSS3", cve.Cvss3).
					Msg("unexpected format")
				continue
			}
			parsedScore, err := strconv.ParseFloat(score, 64)
			if err != nil {
				zlog.Warn(ctx).
					Str("Vulnerability", def.Title).
					Err(err).
					Msg("parsing CVSS3")
				continue
			}
			if parsedScore > cvss3.score {
				cvss3.score = parsedScore
				cvss3.vector = vector
			}
		}

		if cve.Cvss2 != "" {
			score, vector, found := strings.Cut(cve.Cvss2, "/")
			if !found {
				zlog.Warn(ctx).
					Str("CVSS2", cve.Cvss2).
					Msg("unexpected format")
				continue
			}
			parsedScore, err := strconv.ParseFloat(score, 64)
			if err != nil {
				zlog.Warn(ctx).
					Str("Vulnerability", def.Title).
					Err(err).
					Msg("parsing CVSS3")
				continue
			}
			if parsedScore > cvss2.score {
				cvss2.score = parsedScore
				cvss2.vector = vector
			}
		}
	}

	switch {
	case cvss3.score > 0 && cvss3.vector != "":
		return fmt.Sprintf("%.1f/%s", cvss3.score, cvss3.vector)
	case cvss2.score > 0 && cvss2.vector != "":
		return fmt.Sprintf("%.1f/%s", cvss2.score, cvss2.vector)
	default:
		return ""
	}
}
