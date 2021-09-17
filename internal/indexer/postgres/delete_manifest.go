package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v4"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func (s *store) DeleteManifest(ctx context.Context, hash claircore.Digest) error {
	const query = `
DO $$DECLARE
	ts TEXT[] := '{"indexreport","manifest_index","scanned_manifest","manifest_layer","indexreport"}';
	id bigint;
BEGIN
	SELECT manifest.id INTO STRICT id FROM manifest WHERE hash = $1::TEXT;
	FOREACH t IN ARRAY ts
	LOOP
		EXECUTE format('DELETE FROM %I WHERE manifest_id = %L', t, id);
	END LOOP;
	EXECUTE format('DELETE FROM manifest WHERE id = %L', id);
END$$
`
	_, err := s.pool.Exec(ctx, query, hash)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return indexer.ErrNoSuchManifest
	default:
		return idempotent("unexpected error", err)
	}

	return nil
}
