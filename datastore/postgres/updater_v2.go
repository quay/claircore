package postgres

import (
	"context"
	"errors"
	"io"
	"io/fs"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore/updater/driver/v1"
)

type UpdaterV2 struct {
	*MatcherUpdater
	*IndexerUpdater
}

func (u *UpdaterV2) GetLatestUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error) {
	var mOp, iOp []driver.UpdateOperation
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() (err error) {
		mOp, err = u.MatcherUpdater.GetLatestUpdateOperations(ctx)
		return err
	})
	eg.Go(func() (err error) {
		iOp, err = u.IndexerUpdater.GetLatestUpdateOperations(ctx)
		return err
	})
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return append(iOp, mOp...), nil
}

type MatcherUpdater struct {
	pool *pgxpool.Pool
}

func (m *MatcherStore) MatcherUpdaterService(_ context.Context) (*MatcherUpdater, error) {
	return &MatcherUpdater{pool: m.pool}, nil
}

func (u *MatcherUpdater) UpdateEnrichments(ctx context.Context, ref uuid.UUID, kind string, fp driver.Fingerprint, es []driver.EnrichmentRecord) error {
	return nil
}

func (u *MatcherUpdater) UpdateVulnerabilities(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint, vs *driver.ParsedVulnerabilities) error {
	return nil
}

func (u *MatcherUpdater) GetLatestUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error) {
	return nil, nil
}

type IndexerUpdater struct {
	pool *pgxpool.Pool
}

func (i *IndexerStore) IndexerUpdaterService(_ context.Context) (*IndexerUpdater, error) {
	// Setup?
	return &IndexerUpdater{pool: i.pool}, nil
}

func (u *IndexerUpdater) UpdateIndexerMetadata(ctx context.Context, ref uuid.UUID, indexer string, fp driver.Fingerprint, blobs fs.FS) error {
	const op = `datastore/postgres/IndexerUpdater.UpdateIndexerMetadata`

	err := u.pool.BeginTxFunc(ctx, pgx.TxOptions{}, func(tx pgx.Tx) (err error) {
		// New updateOp ID.
		var id int64

		// Create a new updateOp entry with the specified metadata.
		err = tx.BeginFunc(ctx, func(tx pgx.Tx) (err error) {
			query, done := getQuery(ctx, "create_indexer_metadata", &err)
			defer done()
			if err := tx.QueryRow(ctx, query, ref.String(), indexer, fp).Scan(&id); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Create needed blobs and associate them with the new updateOp.
		if err := tx.BeginFunc(ctx, func(tx pgx.Tx) (err error) {
			query, done := getQuery(ctx, "insert_indexer_metadata_blob", &err)
			defer done()
			// Get all the blobs to add. The contract is all regular files in
			// the root.
			ents, err := fs.ReadDir(blobs, ".")
			if err != nil {
				return err
			}
			lo := tx.LargeObjects()

			for _, ent := range ents {
				if !ent.Type().IsRegular() {
					continue
				}
				// Be a little careful inside the loop to not create a scoped
				// err variable.
				name := ent.Name()
				var oid uint32

				oid, err = lo.Create(ctx, 0)
				if err != nil {
					return err
				}
				// add a new row...
				_, err = tx.Exec(ctx, query, id, name, oid)
				if err != nil {
					return err
				}

				dst, derr := lo.Open(ctx, oid, pgx.LargeObjectModeWrite)
				src, serr := blobs.Open(name)
				if derr != nil || serr != nil {
					if dst != nil {
						dst.Close()
					}
					if src != nil {
						src.Close()
					}
					return errors.Join(serr, derr)
				}
				_, err = io.Copy(dst, src)
				dst.Close()
				src.Close()
				if err != nil {
					return err
				}
			}
			return err
		}); err != nil {
			return err
		}

		// Delete any previous updateOps
		if err := tx.BeginFunc(ctx, func(tx pgx.Tx) (err error) {
			query, done := getQuery(ctx, "clean_indexer_metadata", &err)
			defer done()
			// Rely on the database triggers to do unlinks for us.
			_, err = tx.Exec(ctx, query, indexer, id)
			return err
		}); err != nil {
			return err
		}
		return nil
	})
	// map to domain error...
	if err != nil {
		return err
	}
	return nil
}

func (u *IndexerUpdater) GetLatestUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error) {
	return nil, nil
}
