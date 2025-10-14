package alpine

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	cveURLPrefix = "https://security.alpinelinux.org/vuln/"
)

var _ driver.Parser = (*updater)(nil)

func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	slog.InfoContext(ctx, "parse start")
	defer slog.InfoContext(ctx, "parse done")
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
			v.Links = cveURLPrefix + id
			out = append(out, &v)
		}
	}
	return out
}
