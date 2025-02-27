package alma

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/pkg/ovalutil"
)

// Parse implements [driver.Updater].
//
// Parse treats the data inside the provided io.ReadCloser as Red Hat
// flavored OVAL XML. The distribution associated with vulnerabilities
// is configured via the Updater. The repository associated with
// vulnerabilies is based on the affected CPE list.
func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "alma/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("alma: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")
	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		defType, err := ovalutil.GetAlmaDefinitionType(def)
		if err != nil {
			return nil, err
		}
		// Red Hat OVAL data include information about vulnerabilities,
		// that actually don't affect the package in any way. Storing them
		// would increase number of records in DB without adding any value.
		if isSkippableDefinitionType(defType) {
			return []*claircore.Vulnerability{}, nil
		}

		// Go look for the vuln name in the references, fallback to
		// title if not found.
		name := def.Title
		if len(def.References) > 0 {
			name = def.References[0].RefID
		}

		v := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               name,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			Severity:           def.Advisory.Severity,
			NormalizedSeverity: NormalizeSeverity(def.Advisory.Severity),
			Dist:               u.dist,
		}
		return []*claircore.Vulnerability{v}, nil
	}
	vulns, err := ovalutil.RPMDefsToVulns(ctx, &root, protoVulns)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func isSkippableDefinitionType(defType ovalutil.DefinitionType) bool {
	return defType == ovalutil.UnaffectedDefinition || defType == ovalutil.NoneDefinition
}

// NormalizeSeverity maps Red Hat severity strings to claircore's normalized
// serverity levels.
func NormalizeSeverity(severity string) claircore.Severity {
	switch strings.ToLower(severity) {
	case "none":
		return claircore.Unknown
	case "low":
		return claircore.Low
	case "moderate":
		return claircore.Medium
	case "important":
		return claircore.High
	case "critical":
		return claircore.Critical
	default:
		return claircore.Unknown
	}
}
