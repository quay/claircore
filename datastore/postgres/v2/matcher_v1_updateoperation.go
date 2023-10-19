package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// GetUpdateDiff implements [datastore.MatcherV1].
func (s *MatcherV1) GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (_ *driver.UpdateDiff, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()
	if cur == uuid.Nil {
		err = errors.New(`nil uuid is invalid as "current" endpoint`)
		return nil, err
	}

	var ret driver.UpdateDiff

	err = pgx.BeginTxFunc(ctx, s.pool, txRO, s.tx(ctx, `GetDiff`, func(ctx context.Context, tx pgx.Tx) (err error) {
		err = pgx.BeginFunc(ctx, tx, s.call(ctx, `confirm`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
			var discard int
			return tx.QueryRow(ctx, query, prev, cur).Scan(&discard)
		}))
		if err != nil {
			return err
		}

		for _, v := range []struct {
			Attr string
			ID   uuid.UUID
			Dst  *driver.UpdateOperation
		}{
			{Attr: "cur", ID: cur, Dst: &ret.Cur},
			{Attr: "prev", ID: prev, Dst: &ret.Prev},
		} {
			v.Dst.Ref = v.ID
			if v.ID == uuid.Nil {
				continue
			}
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, `populaterefs`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
				err = tx.QueryRow(ctx, query, v.ID).Scan(
					&v.Dst.Updater,
					&v.Dst.Fingerprint,
					&v.Dst.Date,
				)
				return err
			}))
			if err != nil {
				return err
			}
		}

		for _, v := range []struct {
			Attr string
			A, B uuid.UUID
			Dst  *[]claircore.Vulnerability
		}{
			{Attr: "added", A: cur, B: prev, Dst: &ret.Added},
			{Attr: "removed", A: prev, B: cur, Dst: &ret.Removed},
		} {
			if v.A == uuid.Nil {
				continue
			}
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, `load`, func(ctx context.Context, tx pgx.Tx, query string) (err error) {
				rows, err := tx.Query(ctx, query, v.A, v.B)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					i := len(*v.Dst)
					*v.Dst = append(*v.Dst, claircore.Vulnerability{
						Package: &claircore.Package{},
						Dist:    &claircore.Distribution{},
						Repo:    &claircore.Repository{},
					})
					if err = scanVulnerability(&(*v.Dst)[i], rows); err != nil {
						return err
					}
				}
				return rows.Err()
			}))
			if err != nil {
				return err
			}
		}

		return nil
	}))
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

// GetLatestUpdateRef implements [driver.Updater].
func (s *MatcherV1) GetLatestUpdateRef(ctx context.Context, kind driver.UpdateKind) (_ uuid.UUID, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	var name string
	switch kind {
	case "":
		name = `any`
	case driver.EnrichmentKind:
		name = `enrichment`
	case driver.VulnerabilityKind:
		name = `vulnerability`
	}
	var ref uuid.UUID
	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, name, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		return c.QueryRow(ctx, query).Scan(&ref)
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return uuid.Nil, nil
	default:
		return uuid.Nil, err
	}

	return ref, nil
}

// GetLatestUpdateRefs implements [driver.Updater].
func (s *MatcherV1) GetLatestUpdateRefs(ctx context.Context, kind driver.UpdateKind) (_ map[string][]driver.UpdateOperation, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	var name string
	switch kind {
	case "":
		name = `any`
	case driver.EnrichmentKind:
		name = `enrichment`
	case driver.VulnerabilityKind:
		name = `vulnerability`
	}
	ret := make(map[string][]driver.UpdateOperation)

	err = s.pool.AcquireFunc(ctx, s.acquire(ctx, name, func(ctx context.Context, c *pgxpool.Conn, query string) error {
		rows, err := c.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var op driver.UpdateOperation
			err := rows.Scan(
				&op.Updater,
				&op.Ref,
				&op.Fingerprint,
				&op.Date,
			)
			if err != nil {
				return err
			}
			ret[op.Updater] = append(ret[op.Updater], op)
		}
		ev := zlog.Debug(ctx)
		if ev.Enabled() {
			ct := 0
			for _, ops := range ret {
				ct += len(ops)
			}
			ev = ev.Int("count", ct)
		}
		ev.Msg("found updaters")
		return nil
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	default:
		return nil, err
	}

	return ret, nil
}

func (s *MatcherV1) GetUpdateOperations(ctx context.Context, kind driver.UpdateKind, updater ...string) (_ map[string][]driver.UpdateOperation, err error) {
	ctx, done := s.method(ctx, &err)
	defer done()

	var name string
	switch kind {
	case "":
		name = `any`
	case driver.EnrichmentKind:
		name = `enrichment`
	case driver.VulnerabilityKind:
		name = `vulnerability`
	}
	ret := make(map[string][]driver.UpdateOperation)

	err = pgx.BeginTxFunc(ctx, s.pool, txRO, s.tx(ctx, `GetUpdateOperations`, func(ctx context.Context, tx pgx.Tx) (err error) {
		if len(updater) == 0 {
			err = pgx.BeginFunc(ctx, tx, s.call(ctx, `getupdaters`, func(ctx context.Context, tx pgx.Tx, query string) error {
				rows, err := tx.Query(ctx, query)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var u string
					if err := rows.Scan(&u); err != nil {
						return err
					}
					updater = append(updater, u)
				}
				return rows.Err()
			}))
			if err != nil {
				return err
			}
		}

		err = pgx.BeginFunc(ctx, tx, s.call(ctx, name, func(ctx context.Context, tx pgx.Tx, query string) error {
			rows, err := tx.Query(ctx, query, updater)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var uo driver.UpdateOperation
				if err := rows.Scan(
					&uo.Ref,
					&uo.Updater,
					&uo.Fingerprint,
					&uo.Date,
				); err != nil {
					return fmt.Errorf("failed to scan update operation for updater %q: %w", uo.Updater, err)
				}
				ret[uo.Updater] = append(ret[uo.Updater], uo)
			}
			return rows.Err()
		}))
		if err != nil {
			return err
		}
		return nil
	}))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return ret, nil
	default:
		return nil, err
	}

	return ret, nil
}

// TODO(hank) Do this differently.
func scanVulnerability(v *claircore.Vulnerability, row pgx.CollectableRow) error {
	var id uint64
	if err := row.Scan(
		&id,
		&v.Name,
		&v.Updater,
		&v.Description,
		&v.Issued,
		&v.Links,
		&v.Severity,
		&v.NormalizedSeverity,
		&v.Package.Name,
		&v.Package.Version,
		&v.Package.Module,
		&v.Package.Arch,
		&v.Package.Kind,
		&v.Dist.DID,
		&v.Dist.Name,
		&v.Dist.Version,
		&v.Dist.VersionCodeName,
		&v.Dist.VersionID,
		&v.Dist.Arch,
		&v.Dist.CPE,
		&v.Dist.PrettyName,
		&v.ArchOperation,
		&v.Repo.Name,
		&v.Repo.Key,
		&v.Repo.URI,
		&v.FixedInVersion,
	); err != nil {
		return err
	}
	v.ID = strconv.FormatUint(id, 10)
	return nil
}
