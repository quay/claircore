package postgres

import (
	"context"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

func Generate[T any](ctx context.Context, count int) *Generator {
	var p *T
	typ := reflect.TypeOf(p).Elem()
	return &Generator{
		ctx:   ctx,
		count: count,
		which: typ,
		ids:   make([]int64, count),
	}
}

type Generator struct {
	ctx   context.Context
	count int
	which reflect.Type
	ids   []int64
}

func (g *Generator) IDs() []int64 {
	return g.ids
}

func (g *Generator) Exec(tx pgx.Tx) error {
	var query string
	switch g.which {
	case reflect.TypeOf(claircore.Package{}):
		query = `INSERT INTO package SELECT GeneratePackages($1) RETURNING id;`
	case reflect.TypeOf((*indexer.PackageScanner)(nil)).Elem():
		query = `INSERT INTO package SELECT GenerateScanners('package', $1) RETURNING id;`
	case reflect.TypeOf((*indexer.RepositoryScanner)(nil)).Elem():
		query = `INSERT INTO package SELECT GenerateScanners('repository', $1) RETURNING id;`
	case reflect.TypeOf((*indexer.DistributionScanner)(nil)).Elem():
		query = `INSERT INTO package SELECT GenerateScanners('distribution', $1) RETURNING id;`
	case reflect.TypeOf((*indexer.FileScanner)(nil)).Elem():
		query = `INSERT INTO package SELECT GenerateScanners('file', $1) RETURNING id;`
	default:
		return fmt.Errorf("programmer error: unimplemented type: %v", g.which)
	}
	rows, err := tx.Query(g.ctx, query, g.count)
	if err != nil {
		return err
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		if err := rows.Scan(&g.ids[i]); err != nil {
			return err
		}
		i++
	}
	return rows.Err()
}

func CreatePackageScanArtifacts(ctx context.Context, d claircore.Digest, pkgIDs []int64, psIDs []int64) func(pgx.Tx) error {
	return func(tx pgx.Tx) error {
		var id int64
		err := tx.QueryRow(ctx, `INSERT INTO layer (hash) VALUES ($1) RETURNING id;`, d).Scan(&id)
		if err != nil {
			return err
		}

		stride := len(pkgIDs) / 2
		const query = `INSERT INTO package_scanartifact (layer_id, package_id, source_id, scanner_id) VALUES ($1 $2, $3, $4);`
		for i, lim := 0, stride; i < lim; i++ {
			if _, err := tx.Exec(ctx, query, id, pkgIDs[i], pkgIDs[i+stride], psIDs[i%len(psIDs)]); err != nil {
				return err
			}
		}
		return nil
	}
}

// InsertPackages inserts each unique package into the database.
//
// Nested source packages are un-nested and inserted.
func InsertPackages(ctx context.Context, pkgs []claircore.Package) func(pgx.Tx) error {
	const query = `INSERT INTO package (id, kind, name, version, module, arch) VALUES ($1, $2, $3, $4, $5, $6)`
	return func(tx pgx.Tx) error {
		for i, pkg := range pkgs {
			// Source packages
			_, err := tx.Exec(ctx, query,
				&pkg.Source.ID, &pkg.Source.Kind, &pkg.Source.Name, &pkg.Source.Version, &pkg.Source.Module, &pkg.Source.Arch)
			if err != nil {
				return fmt.Errorf("package #%d source (%s): %w", i, pkg.Source.Name, err)
			}

			// Package
			_, err = tx.Exec(ctx, query,
				&pkg.ID, &pkg.Kind, &pkg.Name, &pkg.Version, &pkg.Module, &pkg.Arch)
			if err != nil {
				return fmt.Errorf("package #%d (%s): %w", i, pkg.Name, err)
			}
		}
		return nil
	}
}
