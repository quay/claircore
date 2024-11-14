package gobin

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
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
	badVers := make(map[string]string)
	defer func() {
		if len(badVers) == 0 {
			return
		}
		zlog.Warn(ctx).
			Interface("module_versions", badVers).
			Msg("invalid semantic versions found in binary")
	}()

	// TODO(hank) This package could use canonical versions, but the
	// [claircore.Version] type is lossy for pre-release versions (I'm sorry).

	// TODO(hank) The "go version" is documented as the toolchain that produced
	// the binary, which may be distinct from the version of the stdlib used?
	// Need to investigate.
	// GoVersion only documents "go1.19.2" as an example, but something like
	// "go1.20.12 X:strictfipsruntime" has been seen in the wild, hence the call
	// to [strings.Cut]. This is necessary for accurate vulnerability matching.
	goVer, _, _ := strings.Cut(strings.TrimPrefix(bi.GoVersion, "go"), " ")
	runtimeVer, err := ParseVersion(goVer)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, ErrInvalidSemVer):
		badVers["stdlib"] = bi.GoVersion
	default:
		return fmt.Errorf("error parsing runtime version: %q: %w", bi.GoVersion, err)
	}

	*out = append(*out, &claircore.Package{
		Kind: claircore.BINARY,
		Name: "stdlib",
		// This was previously bi.GoVersion,
		// but it must be changed to ensure an entry
		// with the fixed NormalizedVersion is added to the
		// package table without requiring a migration.
		Version:           goVer,
		PackageDB:         pkgdb,
		Filepath:          p,
		NormalizedVersion: runtimeVer,
	})

	ev := zlog.Debug(ctx)
	vs := map[string]string{
		"stdlib": bi.GoVersion,
	}
	var mmv string
	mainVer, err := ParseVersion(bi.Main.Version)
	switch {
	case errors.Is(err, nil):
	case bi.Main.Version == `(devel)`, bi.Main.Version == ``:
		// This is currently the state of any main module built from source; see
		// the package documentation. Don't record it as a "bad" version and
		// pull out any vcs metadata that's been stamped in.
		mmv = bi.Main.Version
		var v []string
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs":
				v = append(v, s.Value)
			case "vcs.revision":
				switch len(s.Value) {
				case 40, 64:
					v = append(v, "commit "+s.Value)
				default:
					v = append(v, "rev "+s.Value)
				}
			case "vcs.time":
				v = append(v, "built at "+s.Value)
			case "vcs.modified":
				if s.Value == "true" {
					v = append(v, "dirty")
				}
			default:
			}
		}
		switch {
		case len(v) != 0:
			mmv = fmt.Sprintf("(devel) (%s)", strings.Join(v, ", "))
		case mmv == ``:
			mmv = `(devel)` // Not totally sure what else to put here.
		}
	case errors.Is(err, ErrInvalidSemVer):
		badVers[bi.Main.Path] = bi.Main.Version
		mmv = bi.Main.Version
	default:
		return fmt.Errorf("error parsing main version: %q: %w", bi.Main.Version, err)
	}

	// This substitution makes the results look like `go version -m` output.
	name := bi.Main.Path
	if name == "" {
		name = "command-line-arguments"
	}
	*out = append(*out, &claircore.Package{
		Kind:              claircore.BINARY,
		PackageDB:         pkgdb,
		Name:              name,
		Version:           mmv,
		Filepath:          p,
		NormalizedVersion: mainVer,
	})

	if ev.Enabled() {
		vs[bi.Main.Path] = bi.Main.Version
	}
	for _, d := range bi.Deps {
		// Replacements are only evaluated for the main module and seem to only
		// be evaluated once, so this shouldn't be recursive.
		if r := d.Replace; r != nil {
			d = r
		}
		nv, err := ParseVersion(d.Version)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, ErrInvalidSemVer):
			badVers[d.Path] = d.Version
		default:
			return fmt.Errorf("error parsing dep version: %q: %w", d.Version, err)
		}

		*out = append(*out, &claircore.Package{
			Kind:              claircore.BINARY,
			PackageDB:         pkgdb,
			Name:              d.Path,
			Version:           d.Version,
			Filepath:          p,
			NormalizedVersion: nv,
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

var versionRegex = regexp.MustCompile(`^v?([0-9]+)(\.[0-9]+)?(\.[0-9]+)?(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?$`)
var ErrInvalidSemVer = errors.New("invalid semantic version")

// ParseVersion will return a claircore.Version of type semver given
// a valid semantic version. If the string is not a valid semver it
// will return an ErrInvalidSemVer.
func ParseVersion(ver string) (c claircore.Version, err error) {
	m := versionRegex.FindStringSubmatch(ver)
	if m == nil {
		err = ErrInvalidSemVer
		return
	}
	if c.V[1], err = fitInt32(m[1]); err != nil {
		return
	}
	if c.V[2], err = fitInt32(strings.TrimPrefix(m[2], ".")); err != nil {
		return
	}
	if c.V[3], err = fitInt32(strings.TrimPrefix(m[3], ".")); err != nil {
		return
	}
	c.Kind = "semver"
	return
}

func fitInt32(seg string) (int32, error) {
	if len(seg) > 9 {
		// Technically 2147483647 is possible so this should be well within bounds.
		// Slicing here to avoid any big.Int allocations at the expense of a little
		// more accuracy.
		seg = seg[:9]
	}
	if seg == "" {
		return 0, nil
	}
	i, err := strconv.ParseInt(seg, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(i), nil
}
