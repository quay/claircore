package postgres

import (
	"context"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// ArtifactByLayer is a helper that does the "easy" cases of the *ByLayer
// methods.
func artifactByLayer[T artifact](ctx context.Context, s *IndexerV1, hash claircore.Digest, vs indexer.VersionedScanners) (out []T, err error) {
	rvs := rotateVersionedScanners(vs)
	typ := reflect.TypeOf(out).Elem()
	fn := fmt.Sprintf(`helper_%s_bylayer.sql`, typ.Name())
	err = pgx.BeginTxFunc(ctx, s.pool, txRO, s.callfile(ctx, fn, `query`, func(ctx context.Context, tx pgx.Tx, query string) error {
		rows, err := tx.Query(ctx, query, hash, rvs.Name, rvs.Version, rvs.Kind)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[T])
		return err
	}))
	return out, err
}

// PtrSlice returns a slice of pointers to the values in the passed slice.
func ptrSlice[T any](s []T) []*T {
	if s == nil {
		return nil
	}

	out := make([]*T, len(s))
	for i := range s {
		out[i] = &s[i]
	}
	return out
}

// DistributionsByLayer implements [indexer.Store].
func (s *IndexerV1) DistributionsByLayer(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (_ []*claircore.Distribution, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	out, err := artifactByLayer[claircore.Distribution](ctx, s, hash, vs)
	return ptrSlice(out), err
}

// FilesByLayer implements [indexer.Store].
func (s *IndexerV1) FilesByLayer(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (_ []claircore.File, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	out, err := artifactByLayer[claircore.File](ctx, s, hash, vs)
	return out, err
}

// RepositoriesByLayer implements [indexer.Store].
func (s *IndexerV1) RepositoriesByLayer(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (_ []*claircore.Repository, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	out, err := artifactByLayer[claircore.Repository](ctx, s, hash, vs)
	return ptrSlice(out), err
}

// PackagesByLayer implements [indexer.Store].
func (s *IndexerV1) PackagesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) (_ []*claircore.Package, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	// This method is different from the others because Packages are very
	// special.

	var ps []claircore.Package
	lookup := make(map[string]int)
	todo := make(map[string]string)
	rvs := rotateVersionedScanners(scnrs)

	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `query`, func(ctx context.Context, c *pgxpool.Conn, query string) (err error) {
		rows, err := c.Query(ctx, query, hash.String(), rvs.Name, rvs.Version, rvs.Kind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			i := len(ps)
			ps = append(ps, claircore.Package{})
			pkg := &ps[i]

			var srcID, nKind, fPath *string
			err = rows.Scan(
				&pkg.ID,
				&pkg.Name,
				&pkg.Kind,
				&pkg.Version,
				&nKind,
				&pkg.NormalizedVersion,
				&pkg.Module,
				&pkg.Arch,
				&srcID,
				&pkg.PackageDB,
				&pkg.RepositoryHint,
				&fPath,
			)
			if err != nil {
				return err
			}
			lookup[pkg.ID] = i
			if nKind != nil {
				pkg.NormalizedVersion.Kind = *nKind
			}
			if fPath != nil {
				pkg.Filepath = *fPath
			}
			if srcID != nil {
				if si, ok := lookup[*srcID]; ok {
					pkg.Source = &ps[si]
				} else {
					todo[pkg.ID] = *srcID
				}
			}
		}
		return rows.Err()
	}))
	if err != nil {
		return nil, err
	}
	for pkgID, srcID := range todo {
		si, ok := lookup[srcID]
		if !ok {
			continue // No Source ?
		}
		pkg := &ps[lookup[pkgID]]
		pkg.Source = &ps[si]
	}

	return ptrSlice(ps), nil
}
