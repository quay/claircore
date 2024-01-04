package datastore_test

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

// UpdateCmpopts is the [cmp.Options] for [UpdaterV1CompareTest] tests.
var updateCmpopts = cmp.Options{
	// Due to the Store returning the ref ID in this API, we need to
	// ignore the value; it will never match.
	//
	// Similar with "Date" -- it's a database timestamp.
	cmpopts.IgnoreFields(driver.UpdateOperation{}, "Ref", "Date"),
	// These IDs are also created database-side.
	cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID", "Package.ID", "Dist.ID", "Repo.ID"),
}

// UpdaterV1CompareTest is a testcase for the "UpdaterV1"
// ([datastore.MatcherV1Updater]) interface.
type UpdaterV1CompareTest struct {
	Name    string
	Insert  int
	Updates int
}

func (tc *UpdaterV1CompareTest) Run(ctx context.Context, newStore []NewStoreFunc[datastore.MatcherV1]) func(*testing.T) {
	// Turn the testcase name in a unique name for the Updater.
	h := fnv.New64a()
	h.Write([]byte(tc.Name))
	binary.Write(h, binary.BigEndian, int64(tc.Insert))
	binary.Write(h, binary.BigEndian, int64(tc.Updates))
	updaterName := strconv.FormatUint(h.Sum64(), 36)

	// Construct common internal state for the tests.
	tCtx := UpdaterV1Compare{
		Testcase:    tc,
		Updater:     updaterName,
		Fingerprint: driver.Fingerprint(uuid.New().String()),
	}
	return func(t *testing.T) {
		t.Helper()
		t.Parallel()
		// Finish the common internal state construction; make a "PerStore"
		// struct for each store we're comparing.
		for _, f := range newStore {
			s := f(ctx, t).(datastore.MatcherV1Updater)
			typ := reflect.ValueOf(s).Type().String()
			_, name, ok := strings.Cut(typ, ".")
			if !ok {
				t.Fatalf("wild name: %q", typ)
			}
			tCtx.PerStore = append(tCtx.PerStore, UpdaterV1PerStore{
				Store: s,
				Name:  name,
			})
		}

		todo := []func(*testing.T){
			forEachUpdater(ctx, &tCtx, tCtx.Update),
			forEachUpdater(ctx, &tCtx, tCtx.DeltaUpdate),
			forEachUpdater(ctx, &tCtx, tCtx.GetUpdateOperations),
			forEachUpdater(ctx, &tCtx, tCtx.Diff),
			forEachUpdater(ctx, &tCtx, tCtx.DeleteUpdateOperations),
		}
		for _, sub := range todo {
			sub(t)
		}
	}
}

// UpdaterV1Compare is internal state for an [UpdaterV1CompareTest].
type UpdaterV1Compare struct {
	Testcase    *UpdaterV1CompareTest
	Updater     string
	Fingerprint driver.Fingerprint
	PerStore    []UpdaterV1PerStore
}

// UpdaterV1PerStore is state for every [datastore.MatcherV1Updater]
// implementation under test.
type UpdaterV1PerStore struct {
	Store     datastore.MatcherV1Updater
	Name      string
	UpdateOps []driver.UpdateOperation
}

// ForEachUpdater is a generic function that returns a thunk to do comparison of the values returned from the "inner" function.
//
// This is complicated, but allows for us to write the comparison logic in one place.
// The return of "inner" can be any value that doesn't cause problems for go-cmp.
func forEachUpdater[T any](ctx context.Context, ucmp *UpdaterV1Compare, inner TestFunc[datastore.MatcherV1Updater, T]) func(*testing.T) {
	// Do some runtime reflection to pick a name.
	name := runtime.FuncForPC(reflect.ValueOf(inner).Pointer()).Name()
	name = name[strings.LastIndexByte(name, '.')+1:]
	name = strings.TrimSuffix(name, "-fm")

	return func(t *testing.T) {
		if len(ucmp.PerStore) == 1 {
			t.Fatal("only one store implementation provided")
		}
		// Run a subtest named for the function passed in.
		t.Run(name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			got := make([]T, len(ucmp.PerStore))
			for i := range ucmp.PerStore {
				per := &ucmp.PerStore[i]
				out := &got[i]
				// Run a subtest per store instance.
				t.Run(per.Name, func(t *testing.T) {
					ctx := zlog.Test(ctx, t)
					*out = inner(ctx, t, per.Store)
				})
			}
			if t.Failed() {
				t.FailNow()
			}

			// Compare the results pairwise for every combination.
			// This will get slower with more implementations.
			// It may not be necessary to do every combination, but it should be more informative.
			for i, lim := 0, len(ucmp.PerStore); i < lim-1; i++ {
				for j := i + 1; j < lim; j++ {
					a, b := ucmp.PerStore[i], ucmp.PerStore[j]
					aOut, bOut := got[i], got[j]
					ok := cmp.Equal(aOut, bOut, updateCmpopts)
					if !ok {
						t.Errorf("%s ≇ %s", a.Name, b.Name)
						t.Error(cmp.Diff(aOut, bOut, updateCmpopts))
					} else {
						t.Logf("%s ≅ %s", a.Name, b.Name)
					}
				}
			}
		})
	}
}

// Vulns generates Vulnerabilities according to the configuration and name.
func (tc *UpdaterV1CompareTest) vulns(name string) [][]*claircore.Vulnerability {
	// Used as an offset for computed vulnerabilities.
	const opStep = 10
	sz := tc.Insert + (opStep * tc.Updates)
	vs := test.GenUniqueVulnerabilities(sz, name)
	r := make([][]*claircore.Vulnerability, tc.Updates)
	for i := 0; i < tc.Updates; i++ {
		off := i * opStep
		r[i] = vs[off : off+tc.Insert]
	}
	return r
}

// Vulns generates Vulnerabilities according to the configuration.
func (ucmp *UpdaterV1Compare) vulns() [][]*claircore.Vulnerability {
	return ucmp.Testcase.vulns(ucmp.Updater)
}

// Update compares [datastore.MatcherV1Update.UpdateVulnerabilities].
func (ucmp *UpdaterV1Compare) Update(ctx context.Context, t *testing.T, s datastore.MatcherV1Updater) []driver.UpdateOperation {
	vulns := ucmp.vulns()
	out := make([]driver.UpdateOperation, len(vulns))
	for i, vs := range vulns {
		ref, err := s.UpdateVulnerabilities(ctx, ucmp.Updater, ucmp.Fingerprint, vs)
		if err != nil {
			t.Errorf("UpdateVulnerabilities: %v", err)
			continue
		}
		out[i] = driver.UpdateOperation{
			Ref:         ref,
			Fingerprint: ucmp.Fingerprint,
			Updater:     ucmp.Updater,
		}
	}
	return out
}

func (ucmp *UpdaterV1Compare) DeltaUpdate(ctx context.Context, t *testing.T, s datastore.MatcherV1Updater) string {
	t.Skip("TODO")
	return ""
}

// GetUpdateOperations compares [datastore.MatcherV1Update.GetUpdateOperations].
func (ucmp *UpdaterV1Compare) GetUpdateOperations(ctx context.Context, t *testing.T, s datastore.MatcherV1Updater) map[string][]driver.UpdateOperation {
	out, err := s.GetUpdateOperations(ctx, driver.VulnerabilityKind, ucmp.Updater)
	if err != nil {
		t.Errorf("GetUpdateOperations: %v", err)
	}
	return out
}

// Diff compares [datastore.MatcherV1Update.GetUpdateDiff].
func (ucmp *UpdaterV1Compare) Diff(ctx context.Context, t *testing.T, s datastore.MatcherV1Updater) []*driver.UpdateDiff {
	upd, err := s.GetUpdateOperations(ctx, driver.VulnerabilityKind, ucmp.Updater)
	if err != nil {
		t.Errorf("GetUpdateOperations: %v", err)
	}
	ops := upd[ucmp.Updater]
	slices.Reverse(ops)
	out := make([]*driver.UpdateDiff, len(ops))
	for n := range ops {
		// This does a bunch of checks so that the first operation is compared
		// appropriately.
		prev := uuid.Nil
		if n != 0 {
			prev = ops[n-1].Ref
		}
		cur := ops[n].Ref
		t.Logf("GetUpdateDiff(%v, %v)", prev, cur)

		diff, err := s.GetUpdateDiff(ctx, prev, cur)
		if err != nil {
			t.Errorf("GetUpdateDiff: %v", err)
			continue
		}
		out[n] = diff
	}
	return out
}

// DeleteUpdateOperations compares [datastore.MatcherV1Update.DeleteUpdateOperations].
func (ucmp *UpdaterV1Compare) DeleteUpdateOperations(ctx context.Context, t *testing.T, s datastore.MatcherV1Updater) []driver.UpdateOperation {
	upd, err := s.GetUpdateOperations(ctx, driver.VulnerabilityKind, ucmp.Updater)
	if err != nil {
		t.Errorf("GetUpdateOperations: %v", err)
	}
	ops := make([]uuid.UUID, len(upd[ucmp.Updater]))
	for i, op := range upd[ucmp.Updater] {
		ops[i] = op.Ref
	}
	rm, err := s.DeleteUpdateOperations(ctx, ops...)
	if err != nil {
		t.Errorf("DeleteUpdateOperations: %v", err)
	}
	if got, want := rm, int64(len(upd[ucmp.Updater])); got != want {
		t.Errorf("failed to delete UpdateOperations: got: %d, want: %d", got, want)
	}
	upd, err = s.GetUpdateOperations(ctx, driver.VulnerabilityKind, ucmp.Updater)
	if err != nil {
		t.Errorf("GetUpdateOperations: %v", err)
	}
	return upd[ucmp.Updater]
}

// TestMatcherV1Updater compares outputs of [MatcherImplementations] for the "Updater" APIs.
func TestMatcherV1Updater(t *testing.T) {
	integration.NeedDB(t)
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	tt := []UpdaterV1CompareTest{
		{Name: "10Add2", Insert: 10, Updates: 2},
		{Name: "100Add2", Insert: 100, Updates: 2},
		{Name: "10Add20", Insert: 10, Updates: 20},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx, MatcherImplementations))
	}
}
