package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
)

func InsertRepositories(ctx context.Context, pool *pgxpool.Pool, repos []*claircore.Repository) error {
	for _, repo := range repos {
		_, err := pool.Exec(ctx, `INSERT INTO repo
			(id, name, key, uri)
		VALUES
			($1, $2, $3, $4);`,
			&repo.ID, &repo.Name, &repo.Key, &repo.URI)
		if err != nil {
			return fmt.Errorf("failed to insert test repository %v: %v", repo, err)
		}
	}
	return nil
}
