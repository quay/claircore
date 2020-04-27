package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore"
)

func persistManifest(ctx context.Context, pool *pgxpool.Pool, manifest claircore.Manifest) error {
	const (
		insertManifest = `
		INSERT INTO manifest (hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertLayer = `
		INSERT INTO layer (hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING;
		`
		insertManifestLayer = `
		INSERT INTO manifest_layer (manifest_hash, layer_hash, i)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING;
		`
	)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres:persistManifest: failed to create transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, insertManifest, manifest.Hash)
	if err != nil {
		return fmt.Errorf("postgres:persistManifest: failed to insert manifest: %v", err)
	}

	for i, layer := range manifest.Layers {
		_, err = tx.Exec(ctx, insertLayer, layer.Hash)
		if err != nil {
			return fmt.Errorf("postgres:persistManifest: failed to insert layer: %v", err)
		}
		_, err = tx.Exec(ctx, insertManifestLayer, manifest.Hash, layer.Hash, i)
		if err != nil {
			return fmt.Errorf("postgres:persistManifest: failed to insert manifest -> layer link: %v", err)
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("postgres:persisteManifest: failed to commit tx: %v", err)
	}
	return nil
}
