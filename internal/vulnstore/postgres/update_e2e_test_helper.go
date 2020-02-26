package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jmoiron/sqlx"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// checkDeletion confirms an UpdateOperation and associated Vulnerabilitiles
// no longer exist in the database.
func checkDeletion(t *testing.T, db *sqlx.DB, UOID string) {
	// confirm UOID does not exist
	rows, err := db.Query(`
	SELECT id 
	FROM update_operation
	WHERE id = $1
	`, UOID)
	if err != nil {
		t.Errorf("failed to query for vulns: %v", err)
	}
	if rows.Next() {
		t.Errorf("query for update operation with id %v returned rows", UOID)
	}
	rows.Close()

	// confirm vulns deleted
	rows, err = db.Query(`
	SELECT id 
	FROM vuln 
	WHERE uo_id = $1 
	`, UOID)
	if err != nil {
		t.Errorf("failed to query for vulns: %v", err)
		return
	}
	if rows.Next() {
		t.Errorf("query for vulns with ou_id %v returned rows", UOID)
	}
	rows.Close()
}

// checkUpdateOperation confirms an UpdateOperation is created when store.UpdateVulnerabilities is called.
// date fields are ignored
func checkUpdateOperation(t *testing.T, db *sqlx.DB, uo driver.UpdateOperation) {
	var UO driver.UpdateOperation
	// obtain newest UpdateOpeartion from database
	row := db.QueryRow(`SELECT id, updater, fingerprint, date
						FROM update_operation 
						WHERE id = $1 ORDER BY date DESC LIMIT 1;`, uo.ID)
	err := row.Scan(&UO.ID, &UO.Updater, &UO.Fingerprint, &UO.Date)
	if err != nil {
		t.Fatalf("failed to scan UpdateOperation for UOID %v: %v", uo.ID, err)
	}
	if !cmp.Equal(UO, uo, cmpopts.IgnoreFields(driver.UpdateOperation{}, "Date")) {
		t.Errorf("expected UpdateOperation does not match: %v", cmp.Diff(UO, uo))
	}
}

// // checkUpdateOperation confirms an UpdateOperation is created when store.UpdateVulnerabilities is called.
// func checkUpdateOperation(t *testing.T, db *sqlx.DB, uoid, updater string, fingerprint driver.Fingerprint) {
// 	var UO driver.UpdateOperation
// 	// obtain newest UpdateOpeartion from database
// 	row := db.QueryRow(`SELECT id, updater, fingerprint, date
// 						FROM update_operation
// 						WHERE id = $1 ORDER BY date DESC LIMIT 1;`, uoid)
// 	err := row.Scan(&UO.ID, &UO.Updater, &UO.Fingerprint, &UO.Date)
// 	if err != nil {
// 		t.Fatalf("failed to scan UpdateOperation for UOID %v: %v", uoid, err)
// 	}
// 	if UO.ID != uoid {
// 		t.Fatalf("received UO.ID %v expected %v", UO.ID, uoid)
// 	}
// 	if UO.Updater != updater {
// 		t.Fatalf("received UO.Updater %v expected %v", UO.Updater, updater)
// 	}
// 	if UO.Fingerprint != fingerprint {
// 		t.Fatalf("received UO.ID %v expected %v", UO.Fingerprint, fingerprint)
// 	}
// 	if UO.Date.IsZero() {
// 		t.Fatalf("received zero value date value")
// 	}
// }

// checkDisabledVulns confirms all vulns associated with the provided UpdateOperations
// are marked as disabled in the vulnstore
func checkDisabledVulns(t *testing.T, db *sqlx.DB, UOs []driver.UpdateOperation) {
	for _, uo := range UOs {
		rows, err := db.Query(`SELECT active FROM vuln WHERE uo_id = $1`, uo.ID)
		defer rows.Close()
		if err != nil {
			t.Fatalf("received error selecting vulns: %v", err)
		}
		if !rows.Next() {
			t.Fatalf("selecting vulns by uo_id %v returned no rows", uo.ID)
		}
		for rows.Next() {
			var active bool
			err := rows.Scan(&active)
			if err != nil {
				t.Fatalf("received error scanning vuln: %v", err)
			}
			if active {
				t.Fatalf("found active vuln with uo_id %v", uo.ID)
			}
		}
	}
}

// checkInsertedVulns confirms vulnerabilitiles are inserted into the database correctly when
// store.UpdateVulnerabilities is calld.
func checkInsertedVulns(t *testing.T, db *sqlx.DB, uoid string, vulns []*claircore.Vulnerability) {
	expectedVulns := map[string]*claircore.Vulnerability{}
	for _, vuln := range vulns {
		expectedVulns[vuln.Name] = vuln
	}
	queriedVulns := map[string]*claircore.Vulnerability{}
	rows, err := db.Query(`SELECT	
							uo_id,
							hash,
							updater,
							id, 
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
							active
						   FROM vuln
						   WHERE uo_id = $1`, uoid)
	defer rows.Close()
	if err != nil {
		t.Fatalf("failed to query for vulns: %v", err)
	}
	i := 0
	for rows.Next() {
		var uoid string
		var hash string
		var active bool
		vuln := claircore.Vulnerability{
			Package: &claircore.Package{},
			Dist:    &claircore.Distribution{},
			Repo:    &claircore.Repository{},
		}
		err := rows.Scan(&uoid,
			&hash,
			&vuln.Updater,
			&vuln.ID,
			&vuln.Name,
			&vuln.Description,
			&vuln.Links,
			&vuln.Severity,
			&vuln.Package.Name,
			&vuln.Package.Version,
			&vuln.Package.Kind,
			&vuln.Dist.DID,
			&vuln.Dist.Name,
			&vuln.Dist.Version,
			&vuln.Dist.VersionCodeName,
			&vuln.Dist.VersionID,
			&vuln.Dist.Arch,
			&vuln.Dist.CPE,
			&vuln.Dist.PrettyName,
			&vuln.Repo.Name,
			&vuln.Repo.Key,
			&vuln.Repo.URI,
			&vuln.FixedInVersion,
			&active,
		)
		if err != nil {
			t.Fatalf("failed to scan vulnerability: %v", err)
		}
		// confirm record is active
		if !active {
			t.Fatalf("expected vuln %+v to be active", vuln)
		}
		// confirm a hash was generated
		if hash == "" {
			t.Fatalf("failed to identify hash for inserted vulnerability %+v", vuln)
		}
		queriedVulns[vuln.Name] = &vuln
		i++
	}

	// confirm we did not receive unexpected vulns or bad fields
	for name, vuln := range queriedVulns {
		if expectedVuln, ok := expectedVulns[name]; !ok {
			t.Fatalf("received unexpected vuln: %v", vuln.Name)
		} else {
			// compare vuln fields. ignore id's
			if !cmp.Equal(vuln, expectedVuln, cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID", "Package.ID", "Dist.ID", "Repo.ID")) {
				t.Fatalf("%v", cmp.Diff(vuln, expectedVuln))
			}
		}
	}

	// confirm queriedVulns contain all expected vulns
	for name, _ := range expectedVulns {
		if _, ok := queriedVulns[name]; !ok {
			t.Fatalf("expected vuln %v was not found in query", name)
		}
	}
}
