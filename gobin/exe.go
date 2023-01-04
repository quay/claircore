package gobin

import (
	"context"
	"debug/buildinfo"
	"io"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func toPackages(ctx context.Context, out *[]*claircore.Package, p string, r io.ReaderAt) error {
	bi, err := buildinfo.Read(r)
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to open executable")
		return nil
	}
	ctx = zlog.ContextWithValues(ctx, "exe", p)
	pkgdb := "go:" + p

	*out = append(*out, &claircore.Package{
		Kind:      claircore.BINARY,
		Name:      "runtime",
		Version:   bi.GoVersion,
		PackageDB: pkgdb,
	})
	ev := zlog.Debug(ctx)
	vs := map[string]string{
		"runtime": bi.GoVersion,
	}
	*out = append(*out, &claircore.Package{
		Kind:      claircore.BINARY,
		PackageDB: pkgdb,
		Name:      bi.Main.Path,
		Version:   bi.Main.Version,
	})
	if ev.Enabled() {
		vs[bi.Main.Path] = bi.Main.Version
	}
	for _, d := range bi.Deps {
		*out = append(*out, &claircore.Package{
			Kind:      claircore.BINARY,
			PackageDB: pkgdb,
			Name:      d.Path,
			Version:   d.Version,
		})
		if ev.Enabled() {
			vs[d.Path] = d.Version
		}
	}
	ev.
		Interface("versions", vs).
		Msg("analyzed exe")
	return nil
}
