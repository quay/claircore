package alpine

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"unique"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types"
)

const cveURLPrefix = "https://security.alpinelinux.org/vuln/"

var space = unique.Make(cveURLPrefix)

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
				Kind: types.SourcePackage,
			},
			Dist: u.release.Distribution(),
		}
		out = append(out, unpackSecFixes(partial, pkg.Pkg.Secfixes)...)
	}
	return out, nil
}

// UnpackSecFixes creates a [claircore.Vulnerability] for every flaw ID on every
// version.
func unpackSecFixes(partial claircore.Vulnerability, secFixes map[string][]Flaw) []*claircore.Vulnerability {
	out := []*claircore.Vulnerability{}
	for fixedIn, flaws := range secFixes {
		for _, flaw := range flaws {
			v := partial
			v.Name = flaw.String()
			v.FixedInVersion = fixedIn
			v.Links = cveURLPrefix + flaw.String()
			self, aka := flaw.Aliases()
			v.Self = self
			if aka.Valid() {
				v.Aliases = append(v.Aliases, aka)
			}
			out = append(out, &v)
		}
	}
	return out
}
