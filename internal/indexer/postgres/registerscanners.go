package postgres

import (
	"context"
	"fmt"

	"github.com/quay/claircore/internal/indexer"
)

func (s *store) RegisterScanners(ctx context.Context, vs indexer.VersionedScanners) error {
	const (
		insert = `
INSERT
INTO
	scanner (name, version, kind)
VALUES
	($1, $2, $3)
ON CONFLICT
	(name, version, kind)
DO
	NOTHING;
`
		exists = `
SELECT
	EXISTS(
		SELECT
			1
		FROM
			scanner
		WHERE
			name = $1 AND version = $2 AND kind = $3
	);
`
	)

	var ok bool
	var err error
	for _, v := range vs {
		err = s.pool.QueryRow(ctx, exists, v.Name(), v.Version(), v.Kind()).
			Scan(&ok)
		if err != nil {
			return fmt.Errorf("failed getting id for scanner %q: %v", v.Name(), err)
		}
		if ok {
			continue
		}
		_, err = s.pool.Exec(ctx, insert, v.Name(), v.Version(), v.Kind())
		if err != nil {
			return fmt.Errorf("failed to insert scanner %v: %v", v.Name(), err)
		}
	}

	return nil
}
