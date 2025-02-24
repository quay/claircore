package chainguard

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/quay/zlog"
	"io"

	"github.com/quay/claircore"
	"github.com/quay/claircore/updater/secdb"
)

const urlPrefix = "https://images.chainguard.dev/security/"

func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "chainguard/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()

	var db secdb.SecurityDB
	if err := json.NewDecoder(r).Decode(&db); err != nil {
		return nil, err
	}
	return u.parse(ctx, &db)
}

// parse parses the alpine SecurityDB
func (u *updater) parse(ctx context.Context, sdb *secdb.SecurityDB) ([]*claircore.Vulnerability, error) {
	var dist *claircore.Distribution
	switch u.Name() {
	case "chainguard-updater":
		dist = chainguardDist
	case "wolfi-updater":
		dist = wolfiDist
	}
	if dist == nil {
		return nil, fmt.Errorf("chainguard: no distribution found for %s", u.Name())
	}
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
			Dist: dist,
		}
		out = append(out, unpackSecFixes(partial, pkg.Pkg.Secfixes)...)
	}
	return out, nil
}

// unpackSecFixes takes a map of secFixes and creates a claircore.Vulnerability for each all CVEs present.
func unpackSecFixes(partial claircore.Vulnerability, secFixes map[string][]string) []*claircore.Vulnerability {
	out := []*claircore.Vulnerability{}
	for fixedIn, ids := range secFixes {
		for _, id := range ids {
			v := partial
			v.Name = id
			v.FixedInVersion = fixedIn
			v.Links = urlPrefix + id
			out = append(out, &v)
		}
	}
	return out
}
