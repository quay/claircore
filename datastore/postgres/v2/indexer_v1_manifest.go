package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

// IndexManifest implements [indexer.Store].
func (s *IndexerV1) IndexManifest(ctx context.Context, ir *claircore.IndexReport) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	d := ir.Hash.String()
	if d == "" {
		err = errors.New("invalid digest")
		return err
	}
	records := ir.IndexRecords()
	if len(records) == 0 {
		zlog.Warn(ctx).Msg("manifest being indexed has 0 index records")
		return nil
	}

	doAssociate := func(id *uint64, v [4]*uint64) callFunc {
		return func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			_, err = tx.Exec(ctx, query, id, v[2], v[3], d)
			return err
		}
	}

	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadWrite}, s.tx(ctx, `IndexManifest`, func(ctx context.Context, tx pgx.Tx) (err error) {
		const name = `associate`
		var v [4]*uint64
		for i, r := range records {
			if r.Package == nil {
				zlog.Debug(ctx).Int("index", i).Msg("ignoring nil Package")
				continue
			}
			v, err = toValues(*r)
			if err != nil {
				err = fmt.Errorf("received a record with an invalid id: %v", err)
				return err
			}
			if v[0] != nil {
				err = pgx.BeginFunc(ctx, tx, s.call(ctx, name, doAssociate(v[0], v)))
				if err != nil {
					return err
				}
			}
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, name, doAssociate(v[1], v)))
			if err != nil {
				return err
			}
		}
		return nil
	}))
	if err != nil {
		return err
	}
	zlog.Debug(ctx).Msg("manifest indexed")
	return nil
}

// ToValues is a helper method which checks for nil pointers inside an
// IndexRecord before returning an associated pointer to the artifact in
// question.
//
// v[0] source package id or nil
// v[1] package id or nil
// v[2] distribution id or nil
// v[3] repository id or nil
func toValues(r claircore.IndexRecord) ([4]*uint64, error) {
	res := [4]*uint64{}

	if r.Package.Source != nil {
		id, err := strconv.ParseUint(r.Package.Source.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("source package id %v: %v", r.Package.ID, err)
		}
		res[0] = &id
	}

	if r.Package != nil {
		id, err := strconv.ParseUint(r.Package.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("package id %v: %v", r.Package.ID, err)
		}
		res[1] = &id

	}

	if r.Distribution != nil {
		id, err := strconv.ParseUint(r.Distribution.ID, 10, 64)
		if err != nil {
			return res, fmt.Errorf("distribution id %v: %v", r.Distribution.ID, err)
		}
		res[2] = &id
	}

	if r.Repository != nil {
		id, err := strconv.ParseUint(r.Repository.ID, 10, 64)
		if err != nil {
			// return res, fmt.Errorf("repository id %v: %v", r.Package.ID, err)
			return res, nil
		}
		res[3] = &id
	}

	return res, nil
}

// ManifestScanned implements [indexer.Store].
//
// ManifestScanned determines if a manifest has been scanned by ALL the provided
// scanners.
func (s *IndexerV1) ManifestScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanners) (ok bool, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	rvs := rotateVersionedScanners(vs)
	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, `query`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		return c.QueryRow(ctx, query, hash.String(), rvs.Name, rvs.Version, rvs.Kind).Scan(&ok)
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	default:
		return false, err
	}

	return ok, nil
}

// PersistManifest implements [indexer.Store].
func (s *IndexerV1) PersistManifest(ctx context.Context, manifest claircore.Manifest) (err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	layers := make([]string, len(manifest.Layers))
	for i, l := range manifest.Layers {
		layers[i] = l.Hash.String()
	}

	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `Persist`, func(ctx context.Context, tx pgx.Tx) (err error) {
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `insertmanifest`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			_, err = tx.Exec(ctx, query, manifest.Hash)
			return err
		}))
		if err != nil {
			return err
		}

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `insertlayers`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			_, err = tx.Exec(ctx, query, layers)
			return err
		}))
		if err != nil {
			return err
		}

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `associate`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			_, err = tx.Exec(ctx, query, manifest.Hash, layers)
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
