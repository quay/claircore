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

func (s *store) DistributionsByLayer(ctx context.Context, hash claircore.Digest, scnrs indexer.VersionedScanners) ([]*claircore.Distribution, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		query = `
		SELECT dist.id,
			   dist.name,
			   dist.did,
			   dist.version,
			   dist.version_code_name,
			   dist.version_id,
			   dist.arch,
			   dist.cpe,
			   dist.pretty_name
		FROM dist_scanartifact
				 LEFT JOIN dist ON dist_scanartifact.dist_id = dist.id
				 JOIN layer ON layer.hash = $1
		WHERE dist_scanartifact.layer_id = layer.id
		  AND dist_scanartifact.scanner_id = ANY($2);
		`
	)

	if len(scnrs) == 0 {
		return []*claircore.Distribution{}, nil
	}

	// get scanner ids
	scannerIDs := make([]int64, len(scnrs))
	for i, scnr := range scnrs {
		err := s.pool.QueryRow(ctx, selectScanner, scnr.Name(), scnr.Version(), scnr.Kind()).
			Scan(&scannerIDs[i])
		if err != nil {
			return nil, fmt.Errorf("store:distributionseByLayer failed to retrieve scanner ids for scanner %v: %v", scnr, err)
		}
	}

	rows, err := s.pool.Query(ctx, query, hash, scannerIDs)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store:distributionsByLayer no distribution found for hash %v and scanners %v", hash, scnrs)
	default:
		return nil, fmt.Errorf("store:distributionsByLayer failed to retrieve package rows for hash %v and scanners %v: %v", hash, scnrs, err)
	}
	defer rows.Close()

	res := []*claircore.Distribution{}
	for rows.Next() {
		var dist claircore.Distribution

		var id int64
		err := rows.Scan(
			&id,
			&dist.Name,
			&dist.DID,
			&dist.Version,
			&dist.VersionCodeName,
			&dist.VersionID,
			&dist.Arch,
			&dist.CPE,
			&dist.PrettyName,
		)
		dist.ID = strconv.FormatInt(id, 10)
		if err != nil {
			return nil, fmt.Errorf("store:distributionsByLayer failed to scan distribution: %v", err)
		}

		res = append(res, &dist)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
