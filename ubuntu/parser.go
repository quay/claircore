package ubuntu

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/pkg/ovalutil"
)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("ubuntu: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")

	nameLookupFunc := func(def oval.Definition, name *oval.DpkgName) []string {
		// if the dpkginfo_object>name field has a var_ref it indicates
		// a variable lookup for all packages affected by this vuln is necessary.
		//
		// if the name.Ref field is empty it indicates a single package is affected
		// by the vuln and that package's name is in name.Body.
		var ns []string
		if len(name.Ref) == 0 {
			ns = append(ns, name.Body)
			return ns
		}
		_, i, err := root.Variables.Lookup(name.Ref)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("could not lookup variable id")
			return ns
		}
		consts := root.Variables.ConstantVariables[i]
		for _, v := range consts.Values {
			ns = append(ns, v.Body)
		}
		return ns
	}

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
	vulns, err := ovalutil.DpkgDefsToVulns(ctx, &root, protoVulns, nameLookupFunc)
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
