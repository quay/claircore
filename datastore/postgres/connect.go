package postgres

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/poolstats"
)

// Connect initializes a [pgxpool.Pool] based on the connection string.
func Connect(ctx context.Context, connString string, applicationName string) (*pgxpool.Pool, error) {
	const op = `datastore/postgres/Connect`
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrInvalid,
			Message: "failed to parse connection string",
			Inner: &claircore.Error{
				// Permanent because the same connection string should always
				// yield an error.
				Kind:  claircore.ErrPermanent,
				Inner: err,
			},
		}
	}
	const appnameKey = `application_name`
	params := cfg.ConnConfig.RuntimeParams
	if _, ok := params[appnameKey]; !ok {
		params[appnameKey] = applicationName
	}

	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, &claircore.Error{
			Op:      op,
			Kind:    claircore.ErrPrecondition,
			Message: "failed to create connection pool",
			Inner:   err,
		}
	}

	if err := prometheus.Register(poolstats.NewCollector(pool, applicationName)); err != nil {
		zlog.Info(ctx).Msg("pool metrics already registered")
	}

	return pool, nil
}
