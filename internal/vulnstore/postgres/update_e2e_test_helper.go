package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// CheckDeletion confirms an UpdateOperation and entries in the
// association table have been deleted.
func checkDeletion(ctx context.Context, t *testing.T, db *sqlx.DB, id uuid.UUID) {
	var ok bool

	// Check that the update_operation is removed from the table.
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM update_operation WHERE id = $1::uuid);`,
		id).Scan(&ok); err != nil {
		t.Errorf("failed to query for vulns: %v", err)
	}
	if ok {
		t.Errorf("expected operation %q to not exist", id.String())
	}

	// This really shouldn't happen because of the foreign constraint.
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM uo_vuln WHERE uo = $1::uuid);`,
		id).Scan(&ok); err != nil {
		t.Errorf("failed to query for vulns: %v", err)
	}
	if ok {
		t.Errorf("expected operation %q to not exist", id.String())
	}
}

// checkUpdateOperation confirms an UpdateOperation is created when store.UpdateVulnerabilities is called.
// date fields are ignored
func checkUpdateOperation(t *testing.T, db *sqlx.DB, uo driver.UpdateOperation) {
	var UO driver.UpdateOperation
	// obtain newest UpdateOpeartion from database
	row := db.QueryRow(`SELECT ref, updater, fingerprint, date
						FROM update_operation 
						WHERE ref = $1 ORDER BY date DESC LIMIT 1;`, uo.Ref)
	err := row.Scan(&UO.Ref, &UO.Updater, &UO.Fingerprint, &UO.Date)
	if err != nil {
		t.Fatalf("failed to scan UpdateOperation for UOID %v: %v", uo.Ref, err)
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
		rows, err := db.Query(`SELECT EXISTS(SELECT 1 FROM ou_vuln assoc JOIN update_operation uo ON (assoc.uo = uo.id) WHERE uo.ref = $1`, uo.Ref)
		defer rows.Close()
		if err != nil {
			t.Fatalf("received error selecting vulns: %v", err)
		}
		if !rows.Next() {
			t.Fatalf("selecting vulns by uo_id %v returned no rows", uo.Ref)
		}
		for rows.Next() {
			var active bool
			err := rows.Scan(&active)
			if err != nil {
				t.Fatalf("received error scanning vuln: %v", err)
			}
			if active {
				t.Fatalf("found active vuln with uo_id %v", uo.Ref)
			}
		}
	}
}

// checkInsertedVulns confirms vulnerabilitiles are inserted into the database correctly when
// store.UpdateVulnerabilities is calld.
func checkInsertedVulns(ctx context.Context, t *testing.T, db *sqlx.DB, id uuid.UUID, vulns []*claircore.Vulnerability) {
	const query = ` SELECT	
	vuln.hash_kind,
	vuln.hash,
	vuln.updater,
	vuln.id, 
	vuln.name,
	vuln.description,
	vuln.links,
	vuln.severity,
	vuln.package_name,
	vuln.package_version,
	vuln.package_kind,
	vuln.dist_id,
	vuln.dist_name,
	vuln.dist_version,
	vuln.dist_version_code_name,
	vuln.dist_version_id,
	vuln.dist_arch,
	vuln.dist_cpe,
	vuln.dist_pretty_name,
	vuln.repo_name,
	vuln.repo_key,
	vuln.repo_uri,
	vuln.fixed_in_version
FROM uo_vuln
JOIN vuln ON vuln.id = uo_vuln.vuln
WHERE uo_vuln.uo = $1::uuid;`
	expectedVulns := map[string]*claircore.Vulnerability{}
	for _, vuln := range vulns {
		expectedVulns[vuln.Name] = vuln
	}
	queriedVulns := map[string]*claircore.Vulnerability{}
	rows, err := db.QueryContext(ctx, query, id)
	if err != nil {
		t.Fatalf("failed to query for vulns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hashKind string
		var hash []byte
		vuln := claircore.Vulnerability{
			Package: &claircore.Package{},
			Dist:    &claircore.Distribution{},
			Repo:    &claircore.Repository{},
		}
		err := rows.Scan(
			&hashKind,
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
		)
		if err != nil {
			t.Fatalf("failed to scan vulnerability: %v", err)
		}
		// confirm a hash was generated
		if hashKind == "" || len(hash) == 0 {
			t.Fatalf("failed to identify hash for inserted vulnerability %+v", vuln)
		}
		queriedVulns[vuln.Name] = &vuln
	}
	if err := rows.Err(); err != nil {
		t.Error(err)
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
