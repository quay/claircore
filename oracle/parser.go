package oracle

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/pkg/ovalutil"
)

const (
	oracleLinux5Platform = "Oracle Linux 5"
	oracleLinux6Platform = "Oracle Linux 6"
	oracleLinux7Platform = "Oracle Linux 7"
	oracleLinux8Platform = "Oracle Linux 8"
	oracleLinux9Platform = "Oracle Linux 9"
)

// a mapping between oval platform string to claircore distribution
var platformToDist = map[string]*claircore.Distribution{
	oracleLinux5Platform: fiveDist,
	oracleLinux6Platform: sixDist,
	oracleLinux7Platform: sevenDist,
	oracleLinux8Platform: eightDist,
	oracleLinux9Platform: nineDist,
}

var _ driver.Parser = (*Updater)(nil)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "oracle/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("oracle: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")
	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		// In all oracle databases tested a single
		// and correct platform string can be found inside a definition
		// search is for good measure
		proto := claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			Severity:           def.Advisory.Severity,
			NormalizedSeverity: NormalizeSeverity(def.Advisory.Severity),
		}
		vs := []*claircore.Vulnerability{}
		for _, affected := range def.Affecteds {
			for _, platform := range affected.Platforms {
				if d, ok := platformToDist[platform]; ok {
					v := proto
					v.Dist = d
					vs = append(vs, &v)
				}
			}
		}
		if len(vs) == 0 {
			return nil, fmt.Errorf("could not determine dist")
		}

		// Check if the vulnerability only affects a userspace_ksplice package.
		//  These errata should never be applied to a container since ksplice
		//  userspace packages are not supported to be run within a container.
		// If there's at least one ksplice CPE and not all the affected CPEs
		//  are ksplice related, this will cause false positives we can catch.
		//  This should rarely happen; the most common case for this is if one
		//  of the CPEs wasn't parseable.
		kspliceCPEs := 0
		cpes := len(def.Advisory.AffectedCPEList)
		for _, affected := range def.Advisory.AffectedCPEList {
			wfn, err := cpe.Unbind(affected)
			if err != nil {
				// Found a CPE but could not parse it. Log a warning and return
				//  successfully.
				zlog.Warn(ctx).
					Str("def_title", def.Title).
					Str("cpe", affected).
					Msg("could not parse CPE: there may be a false positive match with a userspace_ksplice package")
				return vs, nil
			}
			if wfn.Attr[cpe.Edition].V == "userspace_ksplice" {
				kspliceCPEs++
			}
		}

		switch diff := cpes - kspliceCPEs; {
		case kspliceCPEs == 0:
			// Continue if there are no ksplice CPEs.
		case cpes == 0:
			zlog.Warn(ctx).
				Str("def_title", def.Title).
				Msg("potential false positives: couldn't find CPEs to check for ksplice packages")
		case diff == 0:
			zlog.Debug(ctx).Msg("skipping userspace_ksplice vulnerabilities")
			return nil, nil
		case diff > 0:
			zlog.Warn(ctx).
				Str("def_title", def.Title).
				Msg("potential false positives: OVAL may have a userspace_ksplice CPE which could not be skipped")
		default:
			panic("programmer error")
		}

		return vs, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, &root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, err
}
