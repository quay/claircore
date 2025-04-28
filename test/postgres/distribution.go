package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore"
)

func InsertDistributions(ctx context.Context, pool *pgxpool.Pool, dists []*claircore.Distribution) error {
	for _, dist := range dists {
		_, err := pool.Exec(ctx, `INSERT INTO dist 
			(id, name, did, version, version_code_name, version_id, arch, cpe, pretty_name) 
		VALUES 
			($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			&dist.ID, &dist.Name, &dist.DID, &dist.Version, &dist.VersionCodeName, &dist.VersionID, &dist.Arch, &dist.CPE, &dist.PrettyName)
		if err != nil {
			return fmt.Errorf("failed to insert test distribution %v: %v", dist, err)
		}
	}
	return nil
}
