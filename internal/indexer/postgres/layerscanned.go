package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func layerScanned(ctx context.Context, db *sqlx.DB, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		selectScanned = `SELECT layer_hash FROM scanned_layer WHERE layer_hash = $1 AND scanner_id = $2`
	)

	// TODO Use passed-in Context.
	var scannerID int64
	err := db.Get(&scannerID, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
	if err != nil {
		if err == sql.ErrNoRows {
			// TODO: make error type to handle this case
			return false, fmt.Errorf("scanner name and version not found in store")
		}
		return false, err
	}

	var layerHash claircore.Digest
	err = db.Get(&layerHash, selectScanned, hash, scannerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to select scanartifact with layer hash: %v", err)
	}

	return true, nil
}
