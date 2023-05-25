package alpine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	cveURLPrefix = "https://www.cve.org/CVERecord?id=%s"
)

var _ driver.Parser = (*updater)(nil)

func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "alpine/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()

	var db SecurityDB
	if err := json.NewDecoder(r).Decode(&db); err != nil {
		return nil, err
	}
	return u.parse(ctx, &db)
}

// parse parses the alpine SecurityDB
func (u *updater) parse(ctx context.Context, sdb *SecurityDB) ([]*claircore.Vulnerability, error) {
	out := []*claircore.Vulnerability{}
	for _, pkg := range sdb.Packages {
		if err := ctx.Err(); err != nil {
			return nil, ctx.Err()
		}
		partial := claircore.Vulnerability{
			Updater:            u.Name(),
			NormalizedSeverity: claircore.Unknown,
			Package: &claircore.Package{
				Name: pkg.Pkg.Name,
				Kind: claircore.SOURCE,
			},
			Dist: u.release.Distribution(),
		}
		out = append(out, unpackSecFixes(partial, pkg.Pkg.Secfixes)...)
	}
	return out, nil
}

// unpackSecFixes takes a map of secFixes and creates a claircore.Vulnerability for each all CVEs present.
func unpackSecFixes(partial claircore.Vulnerability, secFixes map[string][]string) []*claircore.Vulnerability {
	out := []*claircore.Vulnerability{}
	for fixedIn, IDs := range secFixes {
		for _, id := range IDs {
			v := partial
			v.Name = id
			v.FixedInVersion = fixedIn
			v.Links = fmt.Sprintf(cveURLPrefix, id)
			out = append(out, &v)
		}
	}
	return out
}
