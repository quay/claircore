package gobin

import (
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	_ "unsafe" // for error linkname tricks

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

//go:linkname errNotGoExe debug/buildinfo.errNotGoExe
var errNotGoExe error

// It's frustrating that there's no good way to check the error returned from
// [buildinfo.Read]. It's either doing a string compare, which will break
// silently if the error's contents are changed, or the linker tricks done here,
// which will break loudly if the error is renamed or built differently.

func toPackages(ctx context.Context, out *[]*claircore.Package, p string, r io.ReaderAt) error {
	bi, err := buildinfo.Read(r)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNotGoExe):
		return nil
	default:
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to open executable")
		return nil
	}
	ctx = zlog.ContextWithValues(ctx, "exe", p)
	pkgdb := "go:" + p

	// TODO(hank) This package could use canonical versions, but the
	// [claircore.Version] type is lossy for pre-release versions (I'm sorry).

	*out = append(*out, &claircore.Package{
		Kind:      claircore.BINARY,
		Name:      "runtime",
		Version:   bi.GoVersion,
		PackageDB: pkgdb,
		Filepath:  p,
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
		Filepath:  p,
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
			Filepath:  p,
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
