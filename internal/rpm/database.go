package rpm

import (
	"context"
	"fmt"
	"io"
	"iter"
	"runtime/trace"
	"strings"
	"sync"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm/rpmdb"
	"github.com/quay/claircore/internal/rpmver"
)

// Database is a handle to an RPM database.
type Database struct {
	pkgdb   string
	cleanup io.Closer
	headers HeaderReader
}

// Packages creates an iterator over the packages in the RPM database,
// translated to [claircore.Package]s.
//
// Continuing the sequence after an error is reported skips the current package
// and processes the next one.
//
// The returned iterator is single-use.
func (db *Database) Packages(ctx context.Context) iter.Seq2[claircore.Package, error] {
	ctx, task := trace.NewTask(ctx, "internal/rpm.Database.PackagesIter")

	seq := func(yield func(claircore.Package, error) bool) {
		defer task.End()

		srcs := map[string]*claircore.Package{
			"(none)": nil,
			"":       nil,
		}
		headers := db.headers.Headers(ctx)
		seq := loadPackageInfo(ctx, headers)
		var ok bool
		ct := 0
		defer func() {
			zlog.Debug(ctx).
				Int("packages", ct).
				Msg("processed rpm db")
		}()
		retErr := func(err error) (cont bool) {
			trace.WithRegion(ctx, "internal/rpm.Database.PackagesYield", func() { cont = yield(claircore.Package{}, err) })
			return cont
		}
		retPkg := func(pkg claircore.Package) (cont bool) {
			trace.WithRegion(ctx, "internal/rpm.Database.PackagesYield", func() { cont = yield(pkg, nil) })
			return cont
		}

		for info, err := range seq {
			if err != nil {
				if !retErr(err) {
					return
				}
				continue
			}

			pkg := claircore.Package{
				Kind:           claircore.BINARY,
				Name:           info.Name,
				Arch:           info.Arch,
				Module:         info.ModuleStream(),
				RepositoryHint: info.Hint(),
				PackageDB:      db.pkgdb,
			}
			v := info.NEVRA()
			pkg.Version = v.EVR()
			printSourceVersionWarning(ctx)

			srcRPM := info.SourceRPM
			// Remove `.(no)src.rpm`
			srcRPM = strings.TrimSuffix(srcRPM, ".rpm")
			srcRPM = strings.TrimSuffix(srcRPM, ".src")
			srcRPM = strings.TrimSuffix(srcRPM, ".nosrc")
			pkg.Source, ok = srcs[srcRPM]
			for !ok {
				v, err := rpmver.Parse(srcRPM)
				if err != nil {
					zlog.Info(ctx).
						Err(err).
						Msg("unable to parse SOURCERPM tag, skipping")
					break
				}
				if v.Name == nil {
					zlog.Info(ctx).
						Msg("no name parse out of SOURCERPM tag, skipping")
					break
				}
				src := claircore.Package{
					Kind:    claircore.SOURCE,
					Name:    *v.Name,
					Version: v.EVR(),
					// Don't want [Info.Hint] here, as it would encode the
					// binary package's checksum in a (synthesized) source
					// package's information.
					PackageDB: db.pkgdb,
				}

				pkg.Source = &src
				srcs[srcRPM] = &src
				ok = true
			}

			ct++
			if !retPkg(pkg) {
				return
			}
		}
	}

	return seq
}

// SourceVersionWarning is a [sync.Once] for controlling the "invalid source
// version" warning log.
//
// BUG(hank) Can't reliably populate the source: there's no NEVR information,
// just a filename that (by convention) is the NVRA. There's an in-flight [PR]
// to rpm to add this information. This package should be updated when that's
// merged.
//
// [PR]: https://github.com/rpm-software-management/rpm/pull/3755
var sourceVersionWarning sync.Once

func printSourceVersionWarning(ctx context.Context) {
	sourceVersionWarning.Do(func() {
		zlog.Warn(ctx).
			Strs("see-also", []string{
				`https://github.com/rpm-software-management/rpm/issues/2796`,
				`https://github.com/rpm-software-management/rpm/discussions/3703`,
				`https://github.com/rpm-software-management/rpm/pull/3755`,
			}).
			Msg("rpm source packages always record 0 epoch; this may cause incorrect matching")
	})
}

// PopulatePathSet adds relevant paths from the RPM database to the provided
// [PathSet].
func (db *Database) populatePathSet(ctx context.Context, s *PathSet) error {
	ctx, task := trace.NewTask(ctx, "internal/rpm.Database.populatePathSet")
	defer task.End()

	seq := loadPackageInfo(ctx, db.headers.Headers(ctx))
	ct := 0
	defer func() {
		zlog.Debug(ctx).
			Int("packages", ct).
			Int("files", s.len()).
			Msg("processed rpm db")
	}()

	for info, err := range seq {
		if err != nil {
			return err
		}
		ct++
		info.InsertIntoSet(s)
	}
	return nil
}

func (db *Database) Close() error {
	if db.cleanup != nil {
		return db.cleanup.Close()
	}
	return nil
}

func (db *Database) String() string {
	return db.pkgdb
}

// LoadPackageInfo maps a sequence yielding package header bytes to a sequence
// yielding package [Info] values.
//
// Any errors from the underlying sequence are passed through, and any errors
// encountered are reported. Continuing after an error is reported starts
// processing the next package header.
func loadPackageInfo(ctx context.Context, headers iter.Seq2[io.ReaderAt, error]) iter.Seq2[Info, error] {
	return func(yield func(Info, error) bool) {
		var h rpmdb.Header

		for r, err := range headers {
			if err != nil {
				if !yield(Info{}, fmt.Errorf("internal/rpm: unable to read header: %w", err)) {
					return
				}
				continue
			}

			h = rpmdb.Header{}
			if err := h.Parse(ctx, r); err != nil {
				if !yield(Info{}, fmt.Errorf("internal/rpm: unable to parse header: %w", err)) {
					return
				}
				continue
			}

			var i Info
			if err := i.Load(ctx, &h); err != nil {
				if !yield(Info{}, fmt.Errorf("internal/rpm: unable to load package information: %w", err)) {
					return
				}
				continue
			}

			// This is *not* an rpm package, it's just a public key stored in the rpm database.
			if i.Name == "gpg-pubkey" {
				continue
			}

			if !yield(i, nil) {
				return
			}
		}
	}
}
