package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/log"
)

// TestE2E performs an end to end test of  update operations and diffing
func TestE2E(t *testing.T) {
	cases := []*e2e{
		{
			updater: "test-updater",
			insertN: 100,
			updateN: 2,
		},
		{
			updater: "test-updater",
			insertN: 1000,
			updateN: 2,
		},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test-case-%d", i), func(t *testing.T) {
			integration.Skip(t)
			ctx, done := context.WithCancel(context.Background())
			defer done()
			ctx = log.TestLogger(ctx, t)
			db, store, teardown := TestStore(ctx, t)
			defer teardown()

			c.ctx = ctx
			c.db = db
			c.s = store

			t.Run("Update", c.update)
			if c.failed {
				t.Fatal()
			}
			t.Run("GetUpdateOperations", c.getUpdateOperations)
			if c.failed {
				t.Fatal()
			}
			t.Run("Diff", c.diff)
			if c.failed {
				t.Fatal()
			}
			t.Run("DeleteUpdateOperations", c.deleteUpdateOperations)
			if c.failed {
				t.Fatal()
			}
		})
	}
}

// e2e implements a multi-phase test ensuring an update operation and
// diff works end to end.
//
// each method on e2e implements the sub-test function signature
// and may be used in a t.Run() subtest invocation.
//
// if a sub-test method fails e2e.failed will be set to true.
type e2e struct {
	// a ctx with a test logger to pass to code under test
	ctx context.Context
	// the updater which is generating update operations
	updater string
	// max number of vulnerabilitiles to insert
	insertN int
	// number of updates
	updateN int
	// list of UpdateOperations in LIFO (stack) order
	updateOps []driver.UpdateOperation
	// db to check sql tables
	db *sqlx.DB
	// store to call updater  methods on
	s vulnstore.Store
	// whether the test case has failed or not
	failed bool
}

// update confirms multiple updates to the vulstore
// do the correct things.
func (e *e2e) update(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	vulns := test.GenUniqueVulnerabilities(e.insertN, e.updater)
	// store generated UpdateOperations in LIFO order because we receive
	// UpdateOperations in date DESC ordering (LIFO) from the db
	// and this makes it easy to iterate over both.
	stack := make([]driver.UpdateOperation, e.updateN, e.updateN)
	for i := e.updateN - 1; i >= 0; i-- {
		fp := driver.Fingerprint(uuid.New().String())
		id, err := e.s.UpdateVulnerabilities(e.ctx, e.updater, fp, vulns)
		if err != nil {
			t.Fatalf("failed to perform update: %v", err)
		}
		// attach generated UpdateOperations to test retrieval
		// date can be ignored. add in stack order to compare
		stack[i] = driver.UpdateOperation{
			Ref:         id,
			Fingerprint: fp,
			Updater:     e.updater,
		}
		// confirm UpdateOperation and vulns inserted
		// correctly into vulnstore.
		checkUpdateOperation(t, e.db, stack[i])
		checkInsertedVulns(e.ctx, t, e.db, id, vulns)
	}
	e.updateOps = stack
	// make sure vulns introduced in updates 1 through N-1 are
	// marked disabled. knock off newest (first) element on stack
	checkDisabledVulns(t, e.db, e.updateOps[1:])
}

// getUpdateOperations confirms retreiving an update
// operation returns the expected results.
func (e *e2e) getUpdateOperations(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	out, err := e.s.GetUpdateOperations(e.ctx, e.updater)
	if err != nil {
		t.Fatalf("failed to get UpdateOperations: %v", err)
	}
	// confirm number of update operations
	if len(out[e.updater]) != e.updateN {
		t.Fatalf("failed to retrieve %v number of update operations. got %v", e.updateN, len(out[e.updater]))
	}
	// confirm retrieved update operations match
	// test generated values
	for i := 0; i > e.updateN; i++ {
		expected := e.updateOps[i]
		retrieved := out[e.updater][i]
		if expected.Ref != retrieved.Ref {
			t.Errorf("expected %v but got %v for ID", expected.Ref, retrieved.Ref)
		}
		if expected.Updater != retrieved.Updater {
			t.Errorf("expected %v but got %v for ID", expected.Updater, retrieved.Updater)
		}
		if expected.Fingerprint != retrieved.Fingerprint {
			t.Errorf("expected %v but got %v for ID", expected.Updater, retrieved.Updater)
		}
	}
}

func (e *e2e) diff(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()

	// we will remove and add one vuln in a new
	// update operation and confirm this is reflected
	// in a diff.

	n := e.insertN + 1
	vulns := test.GenUniqueVulnerabilities(n, e.updater)
	insertedVulns := vulns[1:] // knock off (delete) vuln 0

	// perform update introducing diff
	fp := driver.Fingerprint(uuid.New().String())
	id, err := e.s.UpdateVulnerabilities(e.ctx, e.updater, fp, insertedVulns)
	if err != nil {
		t.Fatalf("failed to perform update to generate diff: %v", err)
	}

	// add newest UO to top of stack
	stack := make([]driver.UpdateOperation, n, n)
	copy(stack[1:], e.updateOps)
	stack[0] = driver.UpdateOperation{
		Ref:         id,
		Fingerprint: fp,
		Updater:     e.updater,
	}
	e.updateOps = stack

	// create diff for newest [0] being applied over second newest [1]
	a, b := e.updateOps[0], e.updateOps[1]
	diff, err := e.s.GetUpdateOperationDiff(e.ctx, a.Ref, b.Ref)
	if err != nil {
		t.Fatalf("received error getting UpdateDiff: %v", err)
	}

	// make sure we see 1 added and 1 remove
	if len(diff.Added) != 1 {
		t.Fatalf("expected diff.Added to have len of 1 but has %v", len(diff.Added))
	}
	if len(diff.Removed) != 1 {
		t.Fatalf("expected diff.Removed to have len of 1 but has %v", len(diff.Removed))
	}
	// make sure update operations match generated test values
	if !cmp.Equal(e.updateOps[0], diff.A, cmpopts.IgnoreFields(driver.UpdateOperation{}, "Date")) {
		t.Errorf("expected UpdateOpeation A does not match diff: %v", cmp.Diff(a, diff.A))
	}
	if !cmp.Equal(e.updateOps[1], diff.B, cmpopts.IgnoreFields(driver.UpdateOperation{}, "Date")) {
		t.Errorf("expected UpdateOpeation A does not match diff: %v", cmp.Diff(b, diff.B))
	}

	// confirm removed and add vulnerabilities are the ones we expect
	removed, added := diff.Removed[0], diff.Added[0]
	if !cmp.Equal(removed, vulns[0], cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID", "Package.ID", "Dist.ID", "Repo.ID")) {
		t.Errorf("unexpected removed vuln returned: %v", cmp.Diff(removed, vulns[0]))
	}
	if !cmp.Equal(added, vulns[n-1], cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID", "Package.ID", "Dist.ID", "Repo.ID")) {
		t.Errorf("unexpected added vuln returned: %v", cmp.Diff(added, vulns[n-1]))
	}
}

// deleteUpdateOperations performs a deletion of all
// UpdateOperations used in the test and confirms
// both the UpdateOperation and vulnerabilitiles are removed
// from the vulnstore.
func (e *e2e) deleteUpdateOperations(t *testing.T) {
	defer func() {
		e.failed = t.Failed()
	}()
	for _, op := range e.updateOps {
		err := e.s.DeleteUpdateOperations(e.ctx, op.Ref)
		if err != nil {
			t.Fatalf("failed to get delete UpdateOperation: %v", err)
		}
		checkDeletion(e.ctx, t, e.db, op.Ref)
	}
}
