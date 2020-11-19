package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v4"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func (s *store) LayerScanned(ctx context.Context, hash claircore.Digest, scnr indexer.VersionedScanner) (bool, error) {
	// TODO(hank) Could this be written as a single query that reports NULL if
	// the scanner isn't present?
	const (
		selectScanner = `
SELECT
	id
FROM
	scanner
WHERE
	name = $1 AND version = $2 AND kind = $3;
`
		selectScanned = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			layer
			JOIN scanned_layer ON
					scanned_layer.layer_id = layer.id
		WHERE
			layer.hash = $1
			AND scanned_layer.scanner_id = $2
	);
`
	)

	var scannerID int64
	err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
		Scan(&scannerID)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return false, fmt.Errorf("scanner %q not found", scnr)
	default:
		return false, err
	}

	var ok bool
	err = s.pool.QueryRow(ctx, selectScanned, hash.String(), scannerID).
		Scan(&ok)
	if err != nil {
		return false, err
	}

	return ok, nil

}
