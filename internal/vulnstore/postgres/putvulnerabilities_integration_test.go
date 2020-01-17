package postgres

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

const (
	selectVulnByUpdater = `SELECT   id,
									updater,
									name,
									description,
									links,
									severity,
									package_name,
									package_version,
									package_kind,
									dist_id,
									dist_name,
									dist_version,
									dist_version_code_name,
									dist_version_id,
									dist_arch,
									dist_cpe,
									dist_pretty_name,
									repo_name,
									repo_key,
									repo_uri,
									fixed_in_version,
									tombstone
							FROM vuln WHERE updater = $1;`
	selectUpdateHash = `SELECT hash FROM updatecursor WHERE updater = $1`
)

// Test_PutVulnerabilities_Tombstone_Bump confirms that adding
// the same vulnerability to the store prevents it from going stale
// indirectly we confirm the datbase is de-duping identical entries on write
func Test_PutVulnerabilities_Tombstone_Bump(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the name of the updater responsible for putting the packages
		updater string
		// a hash indicating the latest vulnDB fetch
		cursorHash1 string
		cursorHash2 string
		// total number of packages for test to generate. we will
		// initially add totalVulns/2 packages to the store giving them a
		// unique tombstone. we will then add the other 1/2. we should
		// expect only totalVulns/2 vulnerabilities to be present in the db
		totalVulns int
	}{
		{
			name:        "10 vulns",
			cursorHash1: "abc",
			cursorHash2: "xyz",
			totalVulns:  10,
		},
		{
			name:        "50 vulns",
			cursorHash1: "abc",
			cursorHash2: "xyz",
			totalVulns:  50,
		},
		{
			name:        "100 vulns",
			cursorHash1: "abc",
			cursorHash2: "xyz",
			totalVulns:  100,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			// generate total unique vulns
			vulns := test.GenUniqueVulnerabilities(table.totalVulns, table.updater)

			// add all vulns into store.
			err := store.PutVulnerabilities(ctx, table.updater, table.cursorHash2, vulns)
			assert.NoError(t, err)

			// add the same set of vulns.
			err = store.PutVulnerabilities(ctx, table.updater, table.cursorHash2, vulns)
			assert.NoError(t, err)

			// retrieve vulns to investigate
			activeVulns := []*claircore.Vulnerability{}
			rows, err := db.Query(selectVulnByUpdater, table.updater)
			if err != nil {
				t.Fatalf("failed to select active vulnerabilities: %v", err)
			}
			for rows.Next() {
				var tombstone string
				v := &claircore.Vulnerability{
					Package: &claircore.Package{},
					Dist:    &claircore.Distribution{},
					Repo:    &claircore.Repository{},
				}

				err := rows.Scan(&v.ID,
					&v.Updater,
					&v.Name,
					&v.Description,
					&v.Links,
					&v.Severity,
					&v.Package.Name,
					&v.Package.Version,
					&v.Package.Kind,
					&v.Dist.DID,
					&v.Dist.Name,
					&v.Dist.Version,
					&v.Dist.VersionCodeName,
					&v.Dist.VersionID,
					&v.Dist.Arch,
					&v.Dist.CPE,
					&v.Dist.PrettyName,
					&v.Repo.Name,
					&v.Repo.Key,
					&v.Repo.URI,
					&v.FixedInVersion,
					&tombstone,
				)
				assert.NoError(t, err)
				assert.NotEmpty(t, tombstone)
				activeVulns = append(activeVulns, v)
			}

			// assert we only have the number of vulnerabilities specified in our test
			assert.Len(t, activeVulns, table.totalVulns)
		})
	}
}

// Test_PutVulnerabilities_Tombstone_Stale confirms if a vulnerability
// is not seen in a subsequent update it is removed from the store
func Test_PutVulnerabilities_Tombstone_Stale(t *testing.T) {
	integration.Skip(t)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		// the name of the test
		name string
		// the name of the updater responsible for putting the packages
		updater string
		// a hash indicating the latest vulnDB fetch
		cursorHash1 string
		cursorHash2 string
		// total number of packages for test to generate. we will
		// initially add totalVulns/2 packages to the store giving them a
		// unique tombstone. we will then add the other 1/2. we should
		// expect only totalVulns/2 vulnerabilities to be present in the db
		totalVulns int
	}{
		{
			name:        "10 vulns",
			cursorHash1: "abc",
			cursorHash2: "xyz",
			totalVulns:  10,
		},
		{
			name:        "50 vulns",
			cursorHash1: "abc",
			cursorHash2: "xyz",
			totalVulns:  50,
		},
		{
			name:        "100 vulns",
			cursorHash1: "abc",
			cursorHash2: "xyz",
			totalVulns:  100,
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, _, teardown := TestStore(ctx, t)
			defer teardown()

			// generate total unique vulns
			vulns := test.GenUniqueVulnerabilities(table.totalVulns, table.updater)

			// put 1/2 the total into the db. these will be written to the store
			// with a unique tombstone.
			n := table.totalVulns / 2
			err := store.PutVulnerabilities(ctx, table.updater, table.cursorHash1, vulns[:n])
			assert.NoError(t, err)

			// put the other half of packages. these will be written to the store with a new
			// unique tombstone. PutVulnerabilities should then remove the previous 1/2 packages
			// as they are "stale".
			err = store.PutVulnerabilities(ctx, table.updater, table.cursorHash2, vulns[n:])
			assert.NoError(t, err)

			// retrieve vulns to investigate
			activeVulns := []*claircore.Vulnerability{}
			rows, err := db.Query(selectVulnByUpdater, table.updater)
			if err != nil {
				t.Fatalf("failed to select active vulnerabilities: %v", err)
			}
			for rows.Next() {
				var tombstone string
				v := &claircore.Vulnerability{
					Package: &claircore.Package{},
					Dist:    &claircore.Distribution{},
					Repo:    &claircore.Repository{},
				}

				err := rows.Scan(&v.ID,
					&v.Updater,
					&v.Name,
					&v.Description,
					&v.Links,
					&v.Severity,
					&v.Package.Name,
					&v.Package.Version,
					&v.Package.Kind,
					&v.Dist.DID,
					&v.Dist.Name,
					&v.Dist.Version,
					&v.Dist.VersionCodeName,
					&v.Dist.VersionID,
					&v.Dist.Arch,
					&v.Dist.CPE,
					&v.Dist.PrettyName,
					&v.Repo.Name,
					&v.Repo.Key,
					&v.Repo.URI,
					&v.FixedInVersion,
					&tombstone,
				)
				assert.NoError(t, err)
				assert.NotEmpty(t, tombstone)
				activeVulns = append(activeVulns, v)
			}

			// assert we only wind up with 1/2 the total packages
			assert.Len(t, activeVulns, n)
			checkVulns(t, n, activeVulns)
			checkUpdateHash(t, db, table.updater, table.cursorHash2)
		})
	}
}

// checkVulns confirms that only vulnerabilities inserted in the second set
// are left in the vulnstore.
func checkVulns(t *testing.T, n int, vulns []*claircore.Vulnerability) {
	for _, vuln := range vulns {
		// infer id off name and make sure its not < n
		tmp := strings.Split(vuln.Name, "-")
		vulnID, err := strconv.Atoi(tmp[2])
		if err != nil {
			t.Fatalf("could not determine id of generated vuln: %v", err)
		}

		if vulnID < n {
			t.Fatalf("found vulnerability with name %v when n is %d", vuln.Name, n)
		}
	}
}

func checkUpdateHash(t *testing.T, db *sqlx.DB, updater string, expectedHash string) {
	var actualHash string
	err := db.Get(&actualHash, selectHash, updater)
	if err != nil {
		t.Fatalf("failed to get hash: %v", err)
	}
}
