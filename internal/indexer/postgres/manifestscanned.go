package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// manifestScanned determines if a manifest has been scanned by ALL the provided
// scnrs.
func manifestScanned(ctx context.Context, db *sqlx.DB, hash claircore.Digest, scnrs indexer.VersionedScanners) (bool, error) {
	const (
		selectScanner = `
		SELECT id
		FROM scanner
		WHERE name = $1
		  AND version = $2
		  AND kind = $3;
		`
		selectScanned = `SELECT scanner_id FROM scanned_manifest WHERE manifest_hash = $1;`
	)

	// TODO Use passed-in Context.
	// get the ids of the scanners we are testing for.
	var expectedIDs []int64
	for _, scnr := range scnrs {
		var id int64
		row := db.QueryRowx(selectScanner, scnr.Name(), scnr.Version(), scnr.Kind())
		err := row.Scan(&id)
		if err != nil {
			return false, fmt.Errorf("store:manifestScanned failed to retrieve expected scanner id for scnr %v: %v", scnr, err)
		}
		expectedIDs = append(expectedIDs, id)
	}

	// get a map of the found ids which have scanned this package
	var temp = []int64{}
	var foundIDs = map[int64]struct{}{}
	err := db.Select(&temp, selectScanned, hash)
	if err != nil {
		return false, fmt.Errorf("store:manifestScanned failed to select scanner IDs for manifest: %v", err)
	}

	// if we are unable to find any scanner ids for this manifest hash, we have
	// never scanned this manifest.
	if len(temp) == 0 {
		return false, nil
	}

	// create foundIDs map from temporary array
	for _, id := range temp {
		foundIDs[id] = struct{}{}
	}

	// compare the expectedIDs array with our foundIDs. if we get a lookup
	// miss we can say the manifest has not been scanned by all the layers provided
	for _, id := range expectedIDs {
		if _, ok := foundIDs[id]; !ok {
			return false, nil
		}
	}

	return true, nil
}
