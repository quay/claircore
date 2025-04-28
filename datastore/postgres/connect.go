package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore/postgres/types"
	"github.com/quay/claircore/pkg/poolstats"
)

// Connect initialize a postgres pgxpool.Pool based on the connection string
func Connect(ctx context.Context, connString string, applicationName string) (*pgxpool.Pool, error) {
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	const appnameKey = `application_name`
	params := cfg.ConnConfig.RuntimeParams
	if _, ok := params[appnameKey]; !ok {
		params[appnameKey] = applicationName
	}
	cfg.AfterConnect = types.ConnectRegisterTypes

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ConnPool: %v", err)
	}

	if err := prometheus.Register(poolstats.NewCollector(pool, applicationName)); err != nil {
		zlog.Info(ctx).Msg("pool metrics already registered")
	}

	return pool, nil
}
