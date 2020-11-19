package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v4"

	"github.com/quay/claircore"
)

func (s *store) IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	const query = `
	SELECT scan_result
	FROM indexreport
			 JOIN manifest ON manifest.hash = $1
	WHERE indexreport.manifest_id = manifest.id;
	`
	// we scan into a jsonbIndexReport which has value/scan method set
	// then type convert back to scanner.domain object
	var jsr jsonbIndexReport

	err := s.pool.QueryRow(ctx, query, hash).Scan(&jsr)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("store:indexReport failed to retrieve index report: %v", err)
	}

	var sr claircore.IndexReport
	sr = claircore.IndexReport(jsr)
	return &sr, true, nil
}
