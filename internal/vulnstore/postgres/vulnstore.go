package postgres

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/pkg/tracing"
	"go.opentelemetry.io/api/trace"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jmoiron/sqlx"
)

// store implements all interfaces in the vulnstore package
type Store struct {
	db *sqlx.DB
	// lower level access to the conn pool
	pool *pgxpool.Pool
	// the tracer to use with this store
	tracer trace.Tracer
}

func NewVulnStore(db *sqlx.DB, pool *pgxpool.Pool) *Store {
	return WithTracer(db, pool, tracing.GetTracer("claircore/vulnstore/postgres"))
}

func WithTracer(db *sqlx.DB, pool *pgxpool.Pool, tracer trace.Tracer) *Store {
	return &Store{
		db:     db,
		pool:   pool,
		tracer: tracer,
	}
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)

// vulnstore.Updater interface methods //

func (s *Store) PutHash(updater string, hash string) error {
	// TODO: once we have a context as parameter to this, we can add a new span, like the other funcs
	err := putHash(s.db, updater, hash)
	if err != nil {
		return fmt.Errorf("failed to put hash: %v", err)
	}
	return nil
}

func (s *Store) GetHash(ctx context.Context, updater string) (string, error) {
	ctx, span := s.tracer.Start(ctx, "GetHash")
	defer span.End()

	v, err := getHash(ctx, s.db, updater)
	if err != nil {
		return "", tracing.HandleError(fmt.Errorf("failed to get hash: %v", err), span)
	}
	return v, nil
}

func (s *Store) PutVulnerabilities(ctx context.Context, updater string, hash string, vulns []*claircore.Vulnerability) error {
	ctx, span := s.tracer.Start(ctx, "PutVulnerabilities")
	defer span.End()

	err := putVulnerabilities(ctx, s.pool, updater, hash, vulns)
	if err != nil {
		return tracing.HandleError(fmt.Errorf("failed to put vulnerabilities: %v", err), span)
	}
	return nil
}

// vulnstore.Vulnerability interface methods //

func (s *Store) Get(ctx context.Context, records []*claircore.ScanRecord, opts vulnstore.GetOpts) (map[int][]*claircore.Vulnerability, error) {
	ctx, span := s.tracer.Start(ctx, "Get")
	defer span.End()

	vulns, err := get(ctx, s.pool, records, opts)
	if err != nil {
		return nil, tracing.HandleError(fmt.Errorf("failed to get vulnerabilites: %v", err), span)
	}
	return vulns, nil
}
