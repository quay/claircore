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
		// These errata should never be applied to a container since ksplice
		// userspace packages are not supported to be run within a container.
		// TODO(DO NOT MERGE): Assume no CPEs is not ksplice. Is this a problem
		//  with the test?
		// TODO(DO NOT MERGE): Is this even the right way to go about this?
		isOnlyKsplice := len(def.Advisory.AffectedCPEList) > 0
		for _, affected := range def.Advisory.AffectedCPEList {
			wfn, err := cpe.Unbind(affected)
			if err != nil {
				// TODO(DO NOT MERGE): Assume unbindable CPE is not a ksplice.
				//  Is this a problem with the test?
				zlog.Warn(ctx).Msg("could not parse CPE")
				isOnlyKsplice = false
				break
			}
			if wfn.Attr[cpe.Edition].V != "userspace_ksplice" {
				isOnlyKsplice = false
				break
			}
		}
		if isOnlyKsplice {
			return nil, fmt.Errorf("vuln is userspace_ksplice")
		}

		return vs, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, &root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, err
}
