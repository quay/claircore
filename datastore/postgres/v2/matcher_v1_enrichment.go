package postgres

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

// UpdateEnrichments creates a new UpdateOperation, inserts the provided
// EnrichmentRecord(s), and ensures enrichments from previous updates are not
// queried by clients.
func (s *MatcherV1) UpdateEnrichments(ctx context.Context, name string, fp driver.Fingerprint, es []driver.EnrichmentRecord) (_ uuid.UUID, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	type digestPair struct {
		Kind   string
		Digest []byte
	}
	hashes := make([]digestPair, len(es))
	func() {
		_, span := tracer.Start(ctx, `doHashes`)
		defer span.End()
		for i := range es {
			hashes[i].Kind, hashes[i].Digest = hashEnrichment(&es[i])
		}
	}()

	var ref uuid.UUID
	err = pgx.BeginTxFunc(ctx, s.pool, txRW, s.tx(ctx, `UpdateEnrichments`, func(ctx context.Context, tx pgx.Tx) (err error) {
		var id uint64
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `create`, func(ctx context.Context, tx pgx.Tx, query string) error {
			if err := tx.QueryRow(ctx, query, name, string(fp)).Scan(&id, &ref); err != nil {
				return err
			}
			return nil
		}))
		if err != nil {
			return fmt.Errorf("unable to create enrichment update operation: %w", err)
		}
		zlog.Debug(ctx).
			Str("ref", ref.String()).
			Msg("update_operation created")

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `insert`, func(ctx context.Context, tx pgx.Tx, query string) error {
			var batch pgx.Batch
			for i := range es {
				batch.Queue(query, hashes[i].Kind, hashes[i].Digest, name, es[i].Tags, es[i].Enrichment)
			}
			res := tx.SendBatch(ctx, &batch)
			defer res.Close()
			for range es {
				if _, err := res.Exec(); err != nil {
					return err
				}
			}
			return nil
		}))
		if err != nil {
			return fmt.Errorf("unable to insert enrichments: %w", err)
		}

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `associate`, func(ctx context.Context, tx pgx.Tx, query string) error {
			var batch pgx.Batch
			for i := range es {
				batch.Queue(query, hashes[i].Kind, hashes[i].Digest, name, id)
			}
			res := tx.SendBatch(ctx, &batch)
			defer res.Close()
			for range es {
				if _, err := res.Exec(); err != nil {
					return err
				}
			}
			return nil
		}))
		if err != nil {
			return fmt.Errorf("unable to associate enrichments: %w", err)
		}

		return nil
	}))
	if err != nil {
		return uuid.Nil, err
	}

	zlog.Debug(ctx).
		Stringer("ref", ref).
		Int("inserted", len(es)).
		Msg("update_operation committed")

	_ = s.pool.AcquireFunc(ctx, s.acquire(ctx, `refresh`, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		if _, err := c.Exec(ctx, query); err != nil {
			// TODO(hank) Log?
			return fmt.Errorf("unable to refresh update operations view: %w", err)
		}
		return nil
	}))

	return ref, nil
}

func hashEnrichment(r *driver.EnrichmentRecord) (k string, d []byte) {
	h := md5.New()
	sort.Strings(r.Tags)
	for _, t := range r.Tags {
		io.WriteString(h, t)
		h.Write([]byte("\x00"))
	}
	h.Write(r.Enrichment)
	return "md5", h.Sum(nil)
}

func (s *MatcherV1) GetEnrichment(ctx context.Context, name string, tags []string) (res []driver.EnrichmentRecord, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	res = make([]driver.EnrichmentRecord, 0, 8) // Guess at capacity.
	err = pgx.BeginTxFunc(ctx, s.pool, txRO, s.call(ctx, `get`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
		rows, err := tx.Query(ctx, query, name, tags)
		if err != nil {
			return err
		}
		for rows.Next() {
			i := len(res)
			res = append(res, driver.EnrichmentRecord{})
			r := &res[i]
			if err := rows.Scan(&r.Tags, &r.Enrichment); err != nil {
				return err
			}
		}
		return rows.Err()
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	default:
		return nil, err
	}
	return res, nil
}