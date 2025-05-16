package rpm

import (
	"context"
	"fmt"
	"io"
	"iter"
	"runtime/trace"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/rpm/rpmdb"
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

		headers := db.headers.Headers(ctx)
		seq := loadPackageInfo(ctx, headers)
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
			// Can't reliably populate the source; there's no NEVR information,
			// just a filename that (by convention) is the NVRA.

			ct++
			if !retPkg(pkg) {
				return
			}
		}
	}

	return seq
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
		var z Info

		for r, err := range headers {
			if err != nil {
				if !yield(z, fmt.Errorf("rpm: unable to read header: %w", err)) {
					return
				}
				continue
			}

			h = rpmdb.Header{}
			if err := h.Parse(ctx, r); err != nil {
				if !yield(z, fmt.Errorf("rpm: unable to parse header: %w", err)) {
					return
				}
				continue
			}

			var i Info
			if err := i.Load(ctx, &h); err != nil {
				if !yield(z, fmt.Errorf("rpm: unable to load package information: %w", err)) {
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
