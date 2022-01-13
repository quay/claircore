package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

// TestE2E performs an end to end test of update operations and diffing
func TestE2E(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)

	cases := []e2e{
		{
			Name:    "10+2",
			Insert:  10,
			Updates: 2,
		},
		{
			Name:    "100+2",
			Insert:  100,
			Updates: 2,
		},
		{
			Name:    "10+20",
			Insert:  10,
			Updates: 20,
		},
	}
	for _, tc := range cases {
		c := &tc
		t.Run(c.Name, c.Run(ctx))
	}
}

// E2e implements a multi-phase test ensuring an update operation and
// diff works end to end.
type e2e struct {
	Name    string
	Insert  int
	Updates int

	// These are all computed values or results that need to hang around between
	// tests.
	updater   string
	s         vulnstore.Store
	pool      *pgxpool.Pool
	updateOps []driver.UpdateOperation
}

func (e *e2e) Run(ctx context.Context) func(*testing.T) {
	h := fnv.New64a()
	h.Write([]byte(e.Name))
	binary.Write(h, binary.BigEndian, e.Insert)
	binary.Write(h, binary.BigEndian, e.Updates)
	e.updater = strconv.FormatUint(h.Sum64(), 36)
	order := []struct {
		Name string
		Test func(context.Context) func(*testing.T)
	}{

		{"Update", e.Update},
		{"GetUpdateOperations", e.GetUpdateOperations},
		{"recordUpdaterUpdateTime", e.recordUpdateTimes},
		{"Diff", e.Diff},
		{"DeleteUpdateOperations", e.DeleteUpdateOperations},
	}
	return func(t *testing.T) {
		pool := TestDB(ctx, t)
		ctx, done := context.WithCancel(ctx)
		defer done()
		e.pool = pool
		e.s = NewVulnStore(pool)
		for _, sub := range order {
			if !t.Run(sub.Name, sub.Test(ctx)) {
				t.FailNow()
			}
		}
	}
}

const (
	opStep = 10
)

func (e *e2e) vulns() [][]*claircore.Vulnerability {
	sz := e.Insert + (opStep * e.Updates)
	vs := test.GenUniqueVulnerabilities(sz, e.updater)
	r := make([][]*claircore.Vulnerability, e.Updates)
	for i := 0; i < e.Updates; i++ {
		off := i * opStep
		r[i] = vs[off : off+e.Insert]
	}
	return r
}

var updateOpCmp = cmpopts.IgnoreFields(driver.UpdateOperation{}, "Date")

// Update confirms multiple updates to the vulstore
// do the correct things.
func (e *e2e) Update(ctx context.Context) func(*testing.T) {
	fp := driver.Fingerprint(uuid.New().String())
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		e.updateOps = make([]driver.UpdateOperation, 0, e.Updates)
		for _, vs := range e.vulns() {
			ref, err := e.s.UpdateVulnerabilities(ctx, e.updater, fp, vs)
			if err != nil {
				t.Fatalf("failed to perform update: %v", err)
			}

			// attach generated UpdateOperations to test retrieval
			// date can be ignored. add in stack order to compare
			e.updateOps = append(e.updateOps, driver.UpdateOperation{
				Ref:         ref,
				Fingerprint: fp,
				Updater:     e.updater,
			})

			checkInsertedVulns(ctx, t, e.pool, ref, vs)
		}
		t.Log("ok")
	}
}

// GetUpdateOperations confirms retrieving an update
// operation returns the expected results.
func (e *e2e) GetUpdateOperations(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		out, err := e.s.GetUpdateOperations(ctx, driver.VulnerabilityKind, e.updater)
		if err != nil {
			t.Fatalf("failed to get UpdateOperations: %v", err)
		}
		// confirm number of update operations
		if got, want := len(out[e.updater]), e.Updates; got != want {
			t.Fatalf("wrong number of update operations: got: %d, want: %d", got, want)
		}
		// confirm retrieved update operations match
		// test generated values
		for i := 0; i < e.Updates; i++ {
			ri := e.Updates - i - 1
			want, got := e.updateOps[ri], out[e.updater][i]
			if !cmp.Equal(want, got, updateOpCmp) {
				t.Fatal(cmp.Diff(want, got, updateOpCmp))
			}
		}
		t.Log("ok")
	}
}

// recordUpdateTimes confirms multiple updates to record last update times
// and then an update to an whole updater set
func (e *e2e) recordUpdateTimes(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		expectedTableContents := make(map[string]time.Time)
		updates := make(map[string]time.Time)
		updates["test-updater-1"] = time.Date(2021, time.Month(2), 21, 1, 10, 30, 0, time.UTC)
		updates["test-updater-2"] = time.Date(2021, time.Month(2), 21, 1, 10, 30, 0, time.UTC)
		updates["test-updater-1"] = time.Date(2021, time.Month(2), 22, 1, 10, 30, 0, time.UTC)
		for updater, updateTime := range updates {
			err := e.s.RecordUpdaterUpdateTime(ctx, updater, updateTime)
			if err != nil {
				t.Fatalf("failed to perform update: %v", err)
			}
			expectedTableContents[updater] = updateTime
		}
		checkUpdateTimes(ctx, t, e.pool, expectedTableContents)

		newUpdaterSetTime := time.Date(2021, time.Month(2), 25, 1, 10, 30, 0, time.UTC)
		e.s.RecordUpdaterSetUpdateTime(ctx, "test", newUpdaterSetTime)
		expectedTableContents["test-updater-1"] = newUpdaterSetTime
		expectedTableContents["test-updater-2"] = newUpdaterSetTime
		checkUpdateTimes(ctx, t, e.pool, expectedTableContents)
		t.Log("ok")
	}
}

var vulnCmp = cmp.Options{
	cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID", "Package.ID", "Dist.ID", "Repo.ID"),
}

func orNoIndex(a int) string {
	if a < 0 {
		return "no index"
	}
	return fmt.Sprintf("index %d", a)
}

// Diff fetches Operation diffs from the database and compares them against
// independently calculated diffs.
func (e *e2e) Diff(ctx context.Context) func(t *testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		for n := range e.vulns() {
			// This does a bunch of checks so that the first operation is
			// compared appropriately.
			prev := uuid.Nil
			if n != 0 {
				prev = e.updateOps[n-1].Ref
			}
			cur := e.updateOps[n].Ref
			t.Logf("comparing %v (%s) and %v (index %d)", prev, orNoIndex(n-1), cur, n)

			diff, err := e.s.GetUpdateDiff(ctx, prev, cur)
			if err != nil {
				t.Fatalf("received error getting UpdateDiff: %v", err)
			}

			expectSz := opStep
			if n == 0 {
				expectSz = e.Insert
			}
			if l := len(diff.Added); l != expectSz {
				t.Fatalf("got: len == %d, want len == %d", l, expectSz)
			}
			if n == 0 {
				expectSz = 0
			}
			if l := len(diff.Removed); l != expectSz {
				t.Fatalf("got: len == %d, want len == %d", l, expectSz)
			}

			// make sure update operations match generated test values
			if prev != diff.Prev.Ref {
				t.Errorf("want: %v, got: %v", diff.Prev.Ref, prev)
			}
			if cur != diff.Cur.Ref {
				t.Errorf("want: %v, got: %v", diff.Cur.Ref, cur)
			}

			// confirm removed and added vulnerabilities are the ones we expect
			pair := e.calcDiff(n)
			if n == 0 {
				pair[0] = []*claircore.Vulnerability{}
			}
			// I can't figure out how to make a cmp.Option that does this.
			added := make([]*claircore.Vulnerability, len(pair[1]))
			for i := range diff.Added {
				added[i] = &diff.Added[i]
			}
			if want, got := pair[1], added; !cmp.Equal(got, want, vulnCmp) {
				t.Error(cmp.Diff(got, want, vulnCmp))
			}

			removed := make([]*claircore.Vulnerability, len(pair[0]))
			for i := range diff.Removed {
				removed[i] = &diff.Removed[i]
			}
			if want, got := pair[0], removed; !cmp.Equal(want, got, vulnCmp) {
				t.Error(cmp.Diff(want, got, vulnCmp))
			}
		}
		t.Log("ok")
	}
}

func (e *e2e) calcDiff(i int) [2][]*claircore.Vulnerability {
	if i >= e.Updates {
		panic(fmt.Sprintf("update %d out of bounds (%d)", i, e.Updates))
	}
	sz := e.Insert + (opStep * e.Updates)
	vs := test.GenUniqueVulnerabilities(sz, e.updater)
	if i == 0 {
		return [...][]*claircore.Vulnerability{{}, vs[:e.Insert]}
	}
	loff, lend := (i-1)*opStep, i*opStep
	roff, rend := loff+e.Insert, lend+e.Insert
	return [...][]*claircore.Vulnerability{vs[loff:lend], vs[roff:rend]}
}

// DeleteUpdateOperations performs a deletion of all UpdateOperations used in
// the test and confirms both the UpdateOperation and vulnerabilities are
// removed from the vulnstore.
func (e *e2e) DeleteUpdateOperations(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		const (
			opExists    = `SELECT EXISTS(SELECT 1 FROM update_operation WHERE ref = $1::uuid);`
			assocExists = `SELECT EXISTS(SELECT 1 FROM uo_vuln JOIN update_operation uo ON (uo_vuln.uo = uo.id) WHERE uo.ref = $1::uuid);`
		)
		var exists bool
		ctx := zlog.Test(ctx, t)
		for _, op := range e.updateOps {
			_, err := e.s.DeleteUpdateOperations(ctx, op.Ref)
			if err != nil {
				t.Fatalf("failed to get delete UpdateOperation: %v", err)
			}

			// Check that the update_operation is removed from the table.
			if err := e.pool.QueryRow(ctx, opExists, op.Ref).Scan(&exists); err != nil {
				t.Errorf("query failed: %v", err)
			}
			t.Logf("operation %v exists: %v", op.Ref, exists)
			if exists {
				t.Error()
			}

			// This really shouldn't happen because of the foreign constraint.
			if err := e.pool.QueryRow(ctx, assocExists, op.Ref).Scan(&exists); err != nil {
				t.Errorf("query failed: %v", err)
			}
			t.Logf("operation %v exists: %v", op.Ref, exists)
			if exists {
				t.Error()
			}
		}
		t.Log("ok")
	}
}

// checkInsertedVulns confirms vulnerabilitiles are inserted into the database correctly when
// store.UpdateVulnerabilities is called.
func checkInsertedVulns(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID, vulns []*claircore.Vulnerability) {
	const query = `SELECT
	vuln.hash_kind,
	vuln.hash,
	vuln.updater,
	vuln.id,
	vuln.name,
	vuln.description,
	vuln.issued,
	vuln.links,
	vuln.normalized_severity,
	vuln.severity,
	vuln.package_name,
	vuln.package_version,
	vuln.package_module,
	vuln.package_arch,
	vuln.package_kind,
	vuln.dist_id,
	vuln.dist_name,
	vuln.dist_version,
	vuln.dist_version_code_name,
	vuln.dist_version_id,
	vuln.dist_arch,
	vuln.dist_cpe,
	vuln.dist_pretty_name,
	vuln.arch_operation,
	vuln.repo_name,
	vuln.repo_key,
	vuln.repo_uri,
	vuln.fixed_in_version
FROM uo_vuln
JOIN vuln ON vuln.id = uo_vuln.vuln
JOIN update_operation uo ON uo.id = uo_vuln.uo
WHERE uo.ref = $1::uuid;`
	expectedVulns := map[string]*claircore.Vulnerability{}
	for _, vuln := range vulns {
		expectedVulns[vuln.Name] = vuln
	}
	rows, err := pool.Query(ctx, query, id)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	queriedVulns := map[string]*claircore.Vulnerability{}
	for rows.Next() {
		var id int64
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
			&id,
			&vuln.Name,
			&vuln.Description,
			&vuln.Issued,
			&vuln.Links,
			&vuln.NormalizedSeverity,
			&vuln.Severity,
			&vuln.Package.Name,
			&vuln.Package.Version,
			&vuln.Package.Module,
			&vuln.Package.Arch,
			&vuln.Package.Kind,
			&vuln.Dist.DID,
			&vuln.Dist.Name,
			&vuln.Dist.Version,
			&vuln.Dist.VersionCodeName,
			&vuln.Dist.VersionID,
			&vuln.Dist.Arch,
			&vuln.Dist.CPE,
			&vuln.Dist.PrettyName,
			&vuln.ArchOperation,
			&vuln.Repo.Name,
			&vuln.Repo.Key,
			&vuln.Repo.URI,
			&vuln.FixedInVersion,
		)
		vuln.ID = strconv.FormatInt(id, 10)
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
	for name, got := range queriedVulns {
		if want, ok := expectedVulns[name]; !ok {
			t.Fatalf("received unexpected vuln: %v", got.Name)
		} else {
			// compare vuln fields. ignore id's
			if !cmp.Equal(want, got, vulnCmp) {
				t.Fatal(cmp.Diff(want, got, vulnCmp))
			}
		}
	}

	// confirm queriedVulns contain all expected vulns
	for name := range expectedVulns {
		if _, ok := queriedVulns[name]; !ok {
			t.Fatalf("expected vuln %v was not found in query", name)
		}
	}
}

// checkUpdateTimes confirms updater update times are upserted into the database correctly when
// store.RecordUpaterUptdateTime is called.
func checkUpdateTimes(ctx context.Context, t *testing.T, pool *pgxpool.Pool, updates map[string]time.Time) {
	const query = `SELECT updater_name, last_update_time
FROM update_time`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	type updateRecord struct {
		updaterName    string
		lastUpdateTime time.Time
	}

	queriedUpdates := make(map[string]time.Time)
	for rows.Next() {
		var updaterName string
		var lastUpdateTime time.Time
		err := rows.Scan(
			&updaterName,
			&lastUpdateTime,
		)
		if err != nil {
			t.Fatalf("failed to scan update: %v", err)
		}
		queriedUpdates[updaterName] = lastUpdateTime
	}
	if err := rows.Err(); err != nil {
		t.Error(err)
	}

	// confirm we did not receive unexpected updates
	for name, got := range queriedUpdates {
		if want, ok := updates[name]; !ok {
			t.Fatalf("received unexpected update: %s %v", name, got)
		} else {
			// compare update time
			if !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		}
	}

	// confirm queriedUpdates contain all expected updates
	for name := range updates {
		if _, ok := queriedUpdates[name]; !ok {
			t.Fatalf("expected update %v was not found in query", name)
		}
	}
}
