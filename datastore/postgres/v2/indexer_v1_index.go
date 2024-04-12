package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/zlog"
)

func indexArtifact[T any](ctx context.Context, s *IndexerV1, tx pgx.Tx, hash claircore.Digest, v indexer.VersionedScanner, as []T) (err error) {
	ras := rotateArtifacts(as)
	typ := reflect.TypeOf(as).Elem()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	var ids []int64

	fn := fmt.Sprintf(`helper_%s_indexartifact.sql`, typ.Name())
	err = pgx.BeginFunc(ctx, tx, s.callfile(ctx, fn, `insert`, func(ctx context.Context, tx pgx.Tx, query string) error {
		rows, err := tx.Query(ctx, query, ras...)
		if err != nil {
			return err
		}
		ids, err = pgx.CollectRows(rows, pgx.RowTo[int64])
		return err
	}))
	if err != nil {
		return err
	}

	fn = fmt.Sprintf(`helper_%s_associateartifact.sql`, typ.Name())
	err = pgx.BeginFunc(ctx, tx, s.callfile(ctx, fn, `associate`, func(ctx context.Context, tx pgx.Tx, query string) error {
		_, err = tx.Exec(ctx, query, ids, hash, v.Name(), v.Version(), v.Kind())
		return err
	}))

	return err
}

// IndexDistributions implements [indexer.Store].
func (s *IndexerV1) IndexDistributions(ctx context.Context, dists []*claircore.Distribution, l *claircore.Layer, v indexer.VersionedScanner) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	zlog.Debug(ctx).
		Str("name", v.Name()).
		Str("version", v.Version()).
		Str("kind", v.Kind()).
		Stringer("layer", l.Hash).
		Send()

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `IndexDistributions`, func(ctx context.Context, tx pgx.Tx) (err error) {
		return indexArtifact[*claircore.Distribution](ctx, s, tx, l.Hash, v, dists)
	}))
	return err
}

// IndexFiles implements [indexer.Store].
func (s *IndexerV1) IndexFiles(ctx context.Context, files []claircore.File, l *claircore.Layer, v indexer.VersionedScanner) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	zlog.Debug(ctx).
		Str("name", v.Name()).
		Str("version", v.Version()).
		Str("kind", v.Kind()).
		Stringer("layer", l.Hash).
		Send()

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `IndexFiles`, func(ctx context.Context, tx pgx.Tx) (err error) {
		return indexArtifact[claircore.File](ctx, s, tx, l.Hash, v, files)
	}))
	return err
}

// IndexRepositories implements [indexer.Store].
func (s *IndexerV1) IndexRepositories(ctx context.Context, repos []*claircore.Repository, l *claircore.Layer, v indexer.VersionedScanner) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	zlog.Debug(ctx).
		Str("name", v.Name()).
		Str("version", v.Version()).
		Str("kind", v.Kind()).
		Stringer("layer", l.Hash).
		Send()

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `IndexRepositories`, func(ctx context.Context, tx pgx.Tx) error {
		return indexArtifact[*claircore.Repository](ctx, s, tx, l.Hash, v, repos)
	}))
	return err
}

var (
	zeroPackage = claircore.Package{}
	emptyNorm   = "{}"
)

// IndexPackages implements [indexer.Store].
//
// IndexPackages indexes all provided packages along with creating a scan artifact.
//
// If a source package is nested inside a binary package we index the source
// package first and then create a relation between the binary package and
// source package.
//
// Scan artifacts are used to determine if a particular layer has been scanned by a
// particular scanner. See the LayerScanned method for more details.
func (s *IndexerV1) IndexPackages(ctx context.Context, pkgs []*claircore.Package, layer *claircore.Layer, scnr indexer.VersionedScanner) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	// Big bespoke routine to rotate the packages.
	insertPrep := struct {
		Name, Kind, Version, Module, Arch, NormKind, NormVersion []*string
	}{
		Name:        make([]*string, 0, len(pkgs)),
		Kind:        make([]*string, 0, len(pkgs)),
		Version:     make([]*string, 0, len(pkgs)),
		Module:      make([]*string, 0, len(pkgs)),
		Arch:        make([]*string, 0, len(pkgs)),
		NormKind:    make([]*string, 0, len(pkgs)),
		NormVersion: make([]*string, 0, len(pkgs)),
	}
	str := make([]byte, 0, 32)
	insertRotate := func(pkg *claircore.Package) {
		insertPrep.Name = append(insertPrep.Name, &pkg.Name)
		insertPrep.Kind = append(insertPrep.Kind, &pkg.Kind)
		insertPrep.Version = append(insertPrep.Version, &pkg.Version)
		insertPrep.Module = append(insertPrep.Module, &pkg.Module)
		insertPrep.Arch = append(insertPrep.Arch, &pkg.Arch)
		if pkg.NormalizedVersion.Kind != "" {
			insertPrep.NormKind = append(insertPrep.NormKind, &pkg.NormalizedVersion.Kind)
			var buf bytes.Buffer
			buf.Grow(32)
			buf.WriteByte('{')
			for i := 0; i < 10; i++ {
				if i != 0 {
					buf.WriteByte(',')
				}
				buf.Write(strconv.AppendInt(str, int64(pkg.NormalizedVersion.V[i]), 10))
			}
			buf.WriteByte('}')
			s := buf.String()
			insertPrep.NormVersion = append(insertPrep.NormVersion, &s)
		} else {
			insertPrep.NormKind = append(insertPrep.NormKind, nil)
			insertPrep.NormVersion = append(insertPrep.NormVersion, &emptyNorm)
		}
	}
	var zOnce sync.Once
	insertSkipCt := 0
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			insertSkipCt++
		}
		if pkg.Source == nil {
			pkg.Source = &zeroPackage
			zOnce.Do(func() { insertRotate(pkg.Source) })
		} else {
			insertRotate(pkg.Source)
		}
		insertRotate(pkg)
	}

	// Same for association.
	associatePrep := struct {
		BinName, BinKind, BinVersion, BinModule, BinArch []*string
		SrcName, SrcKind, SrcVersion, SrcModule, SrcArch []*string
		PkgDB, Hint, Path                                []*string
	}{
		BinName:    make([]*string, 0, len(pkgs)),
		BinKind:    make([]*string, 0, len(pkgs)),
		BinVersion: make([]*string, 0, len(pkgs)),
		BinModule:  make([]*string, 0, len(pkgs)),
		BinArch:    make([]*string, 0, len(pkgs)),
		SrcName:    make([]*string, 0, len(pkgs)),
		SrcKind:    make([]*string, 0, len(pkgs)),
		SrcVersion: make([]*string, 0, len(pkgs)),
		SrcModule:  make([]*string, 0, len(pkgs)),
		SrcArch:    make([]*string, 0, len(pkgs)),
		PkgDB:      make([]*string, 0, len(pkgs)),
		Hint:       make([]*string, 0, len(pkgs)),
		Path:       make([]*string, 0, len(pkgs)),
	}
	associateRotate := func(pkg *claircore.Package) {
		associatePrep.BinName = append(associatePrep.BinName, &pkg.Name)
		associatePrep.BinKind = append(associatePrep.BinKind, &pkg.Kind)
		associatePrep.BinVersion = append(associatePrep.BinVersion, &pkg.Version)
		associatePrep.BinModule = append(associatePrep.BinModule, &pkg.Module)
		associatePrep.BinArch = append(associatePrep.BinArch, &pkg.Arch)
		associatePrep.SrcName = append(associatePrep.SrcName, &pkg.Source.Name)
		associatePrep.SrcKind = append(associatePrep.SrcKind, &pkg.Source.Kind)
		associatePrep.SrcVersion = append(associatePrep.SrcVersion, &pkg.Source.Version)
		associatePrep.SrcModule = append(associatePrep.SrcModule, &pkg.Source.Module)
		associatePrep.SrcArch = append(associatePrep.SrcArch, &pkg.Source.Arch)
		associatePrep.PkgDB = append(associatePrep.PkgDB, &pkg.PackageDB)
		associatePrep.Hint = append(associatePrep.Hint, &pkg.RepositoryHint)
		associatePrep.Path = append(associatePrep.Path, &pkg.Filepath)
	}
	associateSkipCt := 0
	for _, pkg := range pkgs {
		if pkg.Name == "" {
			associateSkipCt++
		}
		associateRotate(pkg)
	}

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `IndexPackages`, func(ctx context.Context, tx pgx.Tx) (err error) {
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `insert`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			var ct int64
			defer func() {
				zlog.Debug(ctx).
					Int("skipped", insertSkipCt).
					Int64("inserted", ct).
					Msg("packages inserted")
			}()
			tag, err := tx.Exec(ctx, query, insertPrep.Name, insertPrep.Kind, insertPrep.Version, insertPrep.NormKind, insertPrep.NormVersion, insertPrep.Module, insertPrep.Arch)
			ct = tag.RowsAffected()
			return err
		}))
		if err != nil {
			return err
		}

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `associate`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			var ct int64
			defer func() {
				zlog.Debug(ctx).
					Int("skipped", associateSkipCt).
					Int64("associated", ct).
					Msg("packages associated")
			}()
			tag, err := tx.Exec(ctx, query,
				associatePrep.BinName, associatePrep.BinKind, associatePrep.BinVersion, associatePrep.BinModule, associatePrep.BinArch,
				associatePrep.SrcName, associatePrep.SrcKind, associatePrep.SrcVersion, associatePrep.SrcModule, associatePrep.SrcArch,
				scnr.Name(), scnr.Version(), scnr.Kind(),
				&layer.Hash,
				associatePrep.PkgDB, associatePrep.Hint, associatePrep.Path,
			)
			ct = tag.RowsAffected()
			return err
		}))
		if err != nil {
			return err
		}

		return nil
	}))
	if err != nil {
		return err
	}
	return nil
}
