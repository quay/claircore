package rhel

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/claircore/rhel/internal/common"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var (
	openshift4CPEPattern = regexp.MustCompile(`^cpe:/a:redhat:openshift:(?P<openshiftVersion>4(\.(?P<minorVersion>\d+))?)(::el\d+)?$`)
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
		if u.shouldSkipDefType(defType) {
			return vs, nil
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
				Severity:           def.Advisory.Severity,
				NormalizedSeverity: common.NormalizeSeverity(def.Advisory.Severity),
				Repo: &claircore.Repository{
					Name: affected,
					CPE:  wfn,
					Key:  repositoryKey,
				},
				Dist: u.dist,
			}
			vs = append(vs, v)

			// If this is an unfixed OpenShift 4.x vulnerability, add a CPE for each minor version
			// below the given minor version.
			// There is only a single OVAL v2 file for all OpenShift 4 versions for each RHEL version,
			// and it is assumed the CPE specified for the vulnerability indicates
			// versions y such that 4.0 <= y <= 4.x are affected, where x is the next,
			// unreleased minor version of OpenShift 4 specified in the CPE.
			//
			// It is expected the CPE is of the form cpe:/a:redhat:openshift:4.x or
			// cpe:/a:redhat:openshift:4.x::el<RHEL version>.
			// For example: cpe:/a:redhat:openshift:4.14 or cpe:/a:redhat:openshift:4.15::el9.
			//
			// Any other OpenShift 4-related CPEs are not supported at this time.
			if defType == ovalutil.CVEDefinition && strings.HasPrefix(affected, "cpe:/a:redhat:openshift:4") {
				if openshiftCPEs, err := allKnownOpenShift4CPEs(affected); err != nil {
					zlog.Warn(ctx).Msgf("Skipping addition of extra OpenShift 4 CPEs for the unpatched vulnerability %q: %v", def.Title, err)
				} else {
					for _, openshiftCPE := range openshiftCPEs {
						wfn, err := cpe.Unbind(openshiftCPE)
						if err != nil {
							return nil, err
						}
						v := *v
						v.Repo = &claircore.Repository{
							Name: openshiftCPE,
							CPE:  wfn,
							Key:  repositoryKey,
						}
						vs = append(vs, &v)
					}
				}
			}
		}
		return vs, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, &root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

// ShouldSkipDefType returns "true" if any of the following is "true":
//
// * defType == ovalutil.UnaffectedDefinition
// * defType == ovalutil.NoneDefinition
// * u.ignoreUnpatched && defType == ovalutil.CVEDefinition
func (u *Updater) shouldSkipDefType(defType ovalutil.DefinitionType) bool {
	return defType == ovalutil.UnaffectedDefinition ||
		defType == ovalutil.NoneDefinition ||
		(u.ignoreUnpatched && defType == ovalutil.CVEDefinition)
}

// AllKnownOpenShift4CPEs returns a slice of other CPEs related to the given Red Hat OpenShift 4 CPE.
// For example, given "cpe:/a:redhat:openshift:4.2", this returns
// ["cpe:/a:redhat:openshift:4.0", "cpe:/a:redhat:openshift:4.1"].
// Note: "cpe:/a:redhat:openshift:4.2" is skipped, as it does not exist.
func allKnownOpenShift4CPEs(cpe string) ([]string, error) {
	// These must all stay in-sync at all times.
	const (
		openshiftVersionIdx = 1
		minorVersionIdx     = 3
		submatchLength      = 5
	)

	match := openshift4CPEPattern.FindStringSubmatch(cpe)
	if len(match) != submatchLength || match[minorVersionIdx] == "" {
		return nil, fmt.Errorf("CPE %q does not match an expected OpenShift 4 CPE format", cpe)
	}

	maxMinorVersion, err := strconv.Atoi(match[minorVersionIdx])
	if err != nil {
		return nil, fmt.Errorf("CPE %q does not match an expected OpenShift 4 CPE format: %w", cpe, err)
	}

	openshiftVersion := match[openshiftVersionIdx]
	cpes := make([]string, 0, maxMinorVersion)
	// Skip maxMinorVersion, as this version of OpenShift 4 does not exist yet.
	for i := 0; i < maxMinorVersion; i++ {
		version := strconv.Itoa(i)
		cpes = append(cpes, strings.Replace(cpe, openshiftVersion, "4."+version, 1))
	}

	return cpes, nil
}
