package postgres

import (
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
)

func InsertRepositories(db *sqlx.DB, repos []*claircore.Repository) error {
	for _, repo := range repos {
		_, err := db.Exec(`INSERT INTO repo
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
