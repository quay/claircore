package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v4"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

func (s *store) RepositoriesByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Repository, error) {
	const query = `
SELECT
	repo.id, repo.name, repo.key, repo.uri, repo.cpe
FROM
	repo_scanartifact
	LEFT JOIN repo ON repo_scanartifact.repo_id = repo.id
	JOIN layer ON layer.hash = $1
WHERE
	repo_scanartifact.layer_id = layer.id
	AND repo_scanartifact.scanner_id = ANY ($2);
`

	if len(scnrs) == 0 {
		return []*claircore.Repository{}, nil
	}
	scannerIDs, err := s.selectScanners(ctx, scnrs)
	if err != nil {
		return nil, fmt.Errorf("store:repositoriesByLayer %v", err)
	}

	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:repositoriesByLayer no repositories found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:repositoriesByLayer failed to retrieve package rows for hash %v and scanners %v: %v", hash, scnrs, err)
	}
	defer rows.Close()

	res := []*claircore.Repository{}
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
