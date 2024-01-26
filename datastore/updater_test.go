package datastore_test

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"reflect"
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
			tCtx.perStore = append(tCtx.perStore, UpdaterV1PerStore{
				store: s,
				name:  name,
			})
		}

		todo := []func(*testing.T){
			forEachStore(ctx, &tCtx, tCtx.Update),
			forEachStore(ctx, &tCtx, tCtx.DeltaUpdate),
			forEachStore(ctx, &tCtx, tCtx.GetUpdateOperations),
			forEachStore(ctx, &tCtx, tCtx.Diff),
			forEachStore(ctx, &tCtx, tCtx.DeleteUpdateOperations),
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
	perStore    []UpdaterV1PerStore
}

func (cmp *UpdaterV1Compare) CmpOpts() cmp.Options          { return updateCmpopts }
func (cmp *UpdaterV1Compare) PerStore() []UpdaterV1PerStore { return cmp.perStore }

// UpdaterV1PerStore is state for every [datastore.MatcherV1Updater]
// implementation under test.
type UpdaterV1PerStore struct {
	store     datastore.MatcherV1Updater
	name      string
	UpdateOps []driver.UpdateOperation
}

func (per UpdaterV1PerStore) Name() string                      { return per.name }
func (per UpdaterV1PerStore) Store() datastore.MatcherV1Updater { return per.store }

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
