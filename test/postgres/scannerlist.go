package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
)

// InsertScannerList is to be used with `test.GenUniqueScanners()`. Inserts
// a ScannerList record for scanner IDs 0...n associated with provided manifest hash
func InsertScannerList(ctx context.Context, pool *pgxpool.Pool, hash claircore.Digest, n int) error {
	for i := 0; i < n; i++ {
		_, err := pool.Exec(ctx,
			`INSERT INTO scannerlist
			 (manifest_id, scanner_id)
			 VALUES ($1, $2)`,
			hash,
			i,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
