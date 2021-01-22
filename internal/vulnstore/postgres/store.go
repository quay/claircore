package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// store implements all interfaces in the vulnstore package
type Store struct {
	pool *pgxpool.Pool
	// Initialized is used as an atomic bool for tracking initialization.
	initialized uint32
}

func NewVulnStore(pool *pgxpool.Pool) *Store {
	return &Store{
		pool: pool,
	}
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)

// UpdateVulnerabilities implements vulnstore.Updater.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	return updateVulnerabilites(ctx, s.pool, updater, fingerprint, vulns)
}

// GetUpdateOperations implements vulnstore.Updater.
func (s *Store) GetUpdateOperations(ctx context.Context, updater ...string) (map[string][]driver.UpdateOperation, error) {
	return getUpdateOperations(ctx, s.pool, updater...)
}

// DeleteUpdateOperations implements vulnstore.Updater.
func (s *Store) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) (int64, error) {
	const query = `DELETE FROM update_operation WHERE ref = ANY($1::uuid[]);`
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/deleteUpdateOperations"))
	if len(id) == 0 {
		return 0, nil
	}

	// Pgx seems unwilling to do the []uuid.UUID → uuid[] conversion, so we're
	// forced to make some garbage here.
	refStr := make([]string, len(id))
	for i := range id {
		refStr[i] = id[i].String()
	}
	tag, err := s.pool.Exec(ctx, query, refStr)
	if err != nil {
		return 0, fmt.Errorf("failed to delete: %w", err)
	}
	return tag.RowsAffected(), nil
}

// GetUpdateOperationDiff implements vulnstore.Updater.
func (s *Store) GetUpdateOperationDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}
func (s *Store) GetUpdateDiff(ctx context.Context, a, b uuid.UUID) (*driver.UpdateDiff, error) {
	return getUpdateDiff(ctx, s.pool, a, b)
}

func (s *Store) GetLatestUpdateRefs(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	return getLatestRefs(ctx, s.pool)
}

// Get implements vulnstore.Vulnerability.
func (s *Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %v", err)
	}
	return vulns, nil
}

func (s *Store) GC(ctx context.Context, keep int) (int64, error) {
	const (
		// GCThrottle sets a limit for the number of update
		// operations deleted in a single GC run.
		GCThrottle = 3

		// this query will return rows of string,[]uuid.UUID where string is the updater's name
		// and []uuid.UUID is a slice of update operation refs exceeding the provided keep value.
		updateOps = `
WITH ordered_ops AS (
    SELECT updater, array_agg(ref ORDER BY date DESC) AS refs FROM update_operation GROUP BY updater
)
SELECT ordered_ops.updater, ordered_ops.refs[$1:]
FROM ordered_ops
WHERE array_length(ordered_ops.refs, 1) > $2;
`

		deleteVulns = `
DELETE FROM vuln WHERE id NOT IN (SELECT vuln FROM uo_vuln);
`
	)

	// keys are updater names, values are a slice of stale
	// update operations.
	m := map[string][]uuid.UUID{}

	// gather any update operations exceeding our keep value.
	// keep+1 is used because PG's array slicing is inclusive,
	// we want to grab all items once after our keep value.
	rows, err := s.pool.Query(ctx, updateOps, keep+1, keep)
	switch err {
	case nil:
	case pgx.ErrNoRows:
		return 0, nil
	default:
		return 0, fmt.Errorf("error querying for update operations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var updater string
		// pgx will not scan directly into a []uuid.UUID
		tmp := pgtype.UUIDArray{}
		err := rows.Scan(&updater, &tmp)
		if err != nil {
			return 0, fmt.Errorf("error scanning update operations: %w", err)
		}
		for _, u := range tmp.Elements {
			m[updater] = append(m[updater], u.Bytes) // this works since [16]byte value is assignable to uuid.UUID
		}

	}

	// delete update operations up until GCThrottle
	var i int
	for updater, refs := range m {
		if i == GCThrottle {
			break
		}
		deleted, err := s.DeleteUpdateOperations(ctx, refs...)
		if err != nil {
			return 0, fmt.Errorf("error deleting update operations: %w", err)
		}
		delete(m, updater)
		if deleted > 0 {
			i++
		}
	}

	// perform a delete of any un-ref'd vulnerabilities.
	// subtly, this cleans up any vulnerabilities un-linked
	// by external calls to vulnstore.DeleteUpdateOperations.
	_, err = s.pool.Exec(ctx, deleteVulns)
	if err != nil {
		return 0, fmt.Errorf("error deleting vulns: %w", err)
	}
	return int64(len(m)), nil

}
