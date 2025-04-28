package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore/indexer"
)

// InsertUniqueScanners inserts each unique scanner into the database. the scanner's primary key (int) is set
// to the index of the scanner in the array.
func InsertUniqueScanners(ctx context.Context, pool *pgxpool.Pool, scnrs indexer.VersionedScanners) error {
	for i, scnr := range scnrs {
		_, err := pool.Exec(ctx, `INSERT INTO scanner (id, kind, name, version) VALUES ($1, $2, $3, $4);`,
			i, scnr.Kind(), scnr.Name(), scnr.Version())
		if err != nil {
			return fmt.Errorf("failed to insert test scanner: %v", err)
		}
	}
	return nil
}
