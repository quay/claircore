package postgres

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func (s *store) SetLayerScanned(ctx context.Context, hash claircore.Digest, vs indexer.VersionedScanner) error {
	const query = `
WITH
	scanner
		AS (
			SELECT
				id
			FROM
				scanner
			WHERE
				name = $2 AND version = $3 AND kind = $4
		),
	layer AS (SELECT id FROM layer WHERE hash = $1)
INSERT
INTO
	scanned_layer (layer_id, scanner_id)
VALUES
	(
		(SELECT id AS layer_id FROM layer),
		(SELECT id AS scanner_id FROM scanner)
	)
ON CONFLICT
	(layer_id, scanner_id)
DO
	NOTHING;
`

	_, err := s.pool.Exec(ctx, query, hash, vs.Name(), vs.Version(), vs.Kind())
	if err != nil {
		return fmt.Errorf("store:setLayerScanned scanner %v: %v", vs, err)
	}

	return nil
}
