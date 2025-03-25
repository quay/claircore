package rpm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm/rpmdb"
)

// InnerDB is the interface that adapters must implement.
type innerDB interface {
	All(context.Context) (iter.Seq[io.ReaderAt], func() error)
	Validate(context.Context) error
}

// NativeAdpater implements [NativeDB].
type nativeAdapter struct {
	innerDB
	cleanup func() error
}

// Close implements [io.Closer].
func (a *nativeAdapter) Close() error {
	errs := make([]error, 0, 2)
	if closer, ok := a.innerDB.(io.Closer); ok {
		errs = append(errs, closer.Close())
	}
	if f := a.cleanup; f != nil {
		errs = append(errs, f())
	}
	return errors.Join(errs...)
}

// NativeDB is an interface for doing in-process examination of rpm an database.
type NativeDB interface {
	io.Closer
	All(context.Context) (iter.Seq[io.ReaderAt], func() error)
}

// PackagesFromDB extracts the packages from the rpm headers provided by
// the database.
//
// The returned iterator takes ownership of the provided [NativeDB] and will
// close it when done.
//
// "Pkgdb" is used to populate "PackageDB" in the returned [claircore.Package]
// instances.
func PackagesFromDB(ctx context.Context, pkgdb string, db NativeDB) (iter.Seq[claircore.Package], func() error) {
	defer trace.StartRegion(ctx, "PackagesFromDB").End()
	var final error

	seq := func(yield func(claircore.Package) bool) {
		var err error
		blobs, dbErr := db.All(ctx)
		seq, parseErr := parseBlob(ctx, blobs)
		defer func() {
			final = errors.Join(err, parseErr(), dbErr(), db.Close())
		}()

		src := make(map[string]*claircore.Package)
		src["(none)"] = nil
		ct := 0

		for info := range seq {
			p := claircore.Package{
				Kind:           claircore.BINARY,
				Name:           info.Name,
				Arch:           info.Arch,
				PackageDB:      pkgdb,
				Module:         info.ModuleStream(),
				Version:        info.EVR(),
				RepositoryHint: info.Hint(),
			}

			if s, ok := src[info.SourceNEVR]; ok {
				p.Source = s
			} else {
				s := strings.TrimSuffix(info.SourceNEVR, ".src.rpm")
				pos := len(s)
				for i := 0; i < 2; i++ {
					pos = strings.LastIndexByte(s[:pos], '-')
					if pos == -1 {
						err = fmt.Errorf("malformed NEVR: %q", info.SourceNEVR)
						return
					}
				}

				srcpkg := claircore.Package{
					Kind:    claircore.SOURCE,
					Name:    s[:pos],
					Version: strings.TrimPrefix(s[pos+1:], "0:"),
					Module:  p.Module,
				}
				src[info.SourceNEVR] = &srcpkg
				p.Source = &srcpkg
			}

			ct++
			if !yield(p) {
				break
			}
		}
		zlog.Debug(ctx).
			Int("packages", ct).
			Int("sources", len(src)).
			Msg("processed rpm db")
	}

	return seq, func() error { return final }
}

// ParseBlob maps every [io.ReaderAt] blob into an [Info] instance.
func parseBlob(ctx context.Context, seq iter.Seq[io.ReaderAt]) (iter.Seq[Info], func() error) {
	var final error
	wrapped := func(yield func(Info) bool) {
		var h rpmdb.Header
		for rd := range seq {
			if err := h.Parse(ctx, rd); err != nil {
				final = fmt.Errorf("internal/rpm: error parsing header: %w", err)
				return
			}

			var info Info
			if err := info.Load(ctx, &h); err != nil {
				final = fmt.Errorf("internal/rpm: error loading header: %w", err)
				return
			}

			if info.Name == "gpg-pubkey" {
				// This is *not* an rpm package. It is just a public key stored in the rpm database.
				// Ignore this "package".
				continue
			}

			if !yield(info) {
				return
			}
		}
	}
	return wrapped, func() error { return final }
}
