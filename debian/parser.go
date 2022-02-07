package debian

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
	ctx = zlog.ContextWithValues(ctx, "component", "debian/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("debian: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")

	sourcesMapFunc := func(_ oval.Definition, name *oval.DpkgName) []string {
		return u.sm.Get(name.Body)
	}

	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		vs := []*claircore.Vulnerability{}
		v := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			NormalizedSeverity: claircore.Unknown,
			Dist:               releaseToDist(u.release),
		}
		vs = append(vs, v)
		return vs, nil
	}
	vulns, err := ovalutil.DpkgDefsToVulns(ctx, &root, protoVulns, sourcesMapFunc)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}
