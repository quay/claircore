package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func repositoriesByLayer(ctx context.Context, db *sqlx.DB, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Repository, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		query = `
		SELECT repo.id,
			   repo.name,
			   repo.key,
			   repo.uri,
			   repo.cpe
		FROM repo_scanartifact
				 LEFT JOIN repo ON repo_scanartifact.repo_id = repo.id
		WHERE repo_scanartifact.layer_hash = '%s'
		  AND repo_scanartifact.scanner_id IN (?);
		`
	)
	// TODO Use passed-in Context.
	if len(scnrs) == 0 {
		return []*claircore.Repository{}, nil
	}
	// get scanner ids
	scannerIDs := []int64{}
	for _, scnr := range scnrs {
		var scannerID int64
		err := db.Get(&scannerID, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
		if err != nil {
			return nil, fmt.Errorf("store:repositoriesByLayer failed to retrieve scanner ids for scnr %v: %v", scnr, err)
		}
		scannerIDs = append(scannerIDs, scannerID)
	}

	res := []*claircore.Repository{}

	// rebind see: https://jmoiron.github.io/sqlx/ "in queries" section
	// we need to format this query since an IN query can only have one bindvar. TODO: confirm this
	withHash := fmt.Sprintf(query, hash)
	inQuery, args, err := sqlx.In(withHash, scannerIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to bind scannerIDs to query: %v", err)
	}
	inQuery = db.Rebind(inQuery)

	rows, err := db.Queryx(inQuery, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("store:repositoriesByLayer no repositories found for hash %v and scnrs %v", hash, scnrs)
		}
		return nil, fmt.Errorf("store:repositoriesByLayer failed to retrieve package rows for hash %v and scanners %v: %v", hash, scnrs, err)
	}
	defer rows.Close()

	for rows.Next() {
		var repo claircore.Repository

		var id int64
		err := rows.Scan(
			&id,
			&repo.Name,
			&repo.Key,
			&repo.URI,
			&repo.CPE,
		)
		repo.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("store:repositoriesByLayer failed to scan repositories: %v", err)
		}

		res = append(res, &repo)
	}

	return res, nil
}
