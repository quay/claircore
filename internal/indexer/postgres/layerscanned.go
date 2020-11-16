package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func layerScanned(ctx context.Context, pool *pgxpool.Pool, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		selectScanned = `
		SELECT layer.hash
		FROM layer
                 JOIN scanned_layer ON scanned_layer.layer_hash = layer.id
		WHERE layer.hash = $1
		  AND scanned_layer.scanner_id = $2;
		`
	)

	var scannerID int64
	row := pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
	err := row.Scan(&scannerID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, fmt.Errorf("scanner name and version not found in store: %+v", scnr)
		}
		return false, err
	}

	var layerHash string
	row = pool.QueryRow(ctx, selectScanned, hash.String(), scannerID)
	err = row.Scan(&layerHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	return true, nil

}
