package alpine

import (
	"context"
	"fmt"
	"io"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	nvdURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s"
)

var _ driver.Parser = (*Updater)(nil)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "apline/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()

	var sdb SecurityDB
	err := sdb.Parse(r)
	if err != nil {
		return nil, err
	}

	return u.parse(ctx, &sdb)
}

// parse parses the alpine SecurityDB
func (u *Updater) parse(ctx context.Context, sdb *SecurityDB) ([]*claircore.Vulnerability, error) {
	out := []*claircore.Vulnerability{}
	for _, pkg := range sdb.Packages {
		if err := ctx.Err(); err != nil {
			return nil, ctx.Err()
		}
		partial := claircore.Vulnerability{
			Package: &claircore.Package{
				Name: pkg.Pkg.Name,
			},
			Dist: &claircore.Distribution{
				VersionCodeName: string(u.repo),
				VersionID:       string(u.release),
				Version:         string(u.release),
				DID:             ID,
				Name:            Name,
				PrettyName:      ReleaseToPrettyName[u.release],
			},
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
			v.Links = fmt.Sprintf(nvdURLPrefix, id)
			out = append(out, &v)
		}
	}
	return out
}
