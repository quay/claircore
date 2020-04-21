package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func setLayerScanned(ctx context.Context, pool *pgxpool.Pool, hash claircore.Digest, scnr indexer.VersionedScanner) error {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		query = `
		INSERT INTO scanned_layer (layer_hash, scanner_id)
		VALUES ($1, $2)
		ON CONFLICT (layer_hash, scanner_id) DO NOTHING;
		`
	)

	// get scanner id
	row := pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
	var scannerID int64
	err := row.Scan(&scannerID)
	switch {
	case err == pgx.ErrNoRows:
		return fmt.Errorf("store:setLayerScanned scnr %v: does not exist", scnr)
	case err != nil:
		return fmt.Errorf("store:setLayerScanned failed to retrieve scanner ids for scnr %v: %v", scnr, err)
	}

	_, err = pool.Exec(ctx, query, hash, scannerID)
	if err != nil {
		return fmt.Errorf("store:setLayerScanned scnr %v: %v", scnr, err)
	}

	return nil
}
