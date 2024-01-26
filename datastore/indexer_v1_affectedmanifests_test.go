package datastore_test

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/zlog"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/integration"
)

// TestIndexerV1Affected compares outputs of [IndexerImplementations] for the "AffectedManifest" APIs.
func TestIndexerV1Affected(t *testing.T) {
	integration.NeedDB(t)
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	tt := []IndexerV1AffectedTest{
		{Name: "AffectedTODO"},
	}
	for _, tc := range tt {
		ar, err := txtar.ParseFile(filepath.Join("testdata", tc.Name+".txtar"))
		if err != nil {
			t.Error(err)
			continue
		}
		t.Run(tc.Name, tc.Run(ctx, IndexerImplementations, ar))
	}
}

type IndexerV1AffectedTest struct {
	Name string
}

func (tc *IndexerV1AffectedTest) Run(ctx context.Context, newStore []NewStoreFunc[datastore.IndexerV1], ar *txtar.Archive) func(*testing.T) {
	const fixtureName = `Fixture`
	tcmp := IndexerV1AffectedCompare{
		Testcase: tc,
		Archive:  ar,
	}
	return func(t *testing.T) {
		t.Helper()
		t.Parallel()

		var err error
		for _, f := range tcmp.Archive.Files {
			switch f.Name {
			case fixtureName:
				tcmp.Fixture, err = ParseFixture(fixtureName, bytes.NewReader(f.Data))
			default:
			}
		}
		switch {
		case err != nil:
			t.Fatal(err)
		case tcmp.Fixture == nil:
			t.Fatalf("couldn't find input %q", fixtureName)
		}

		// Finish the common internal state construction; make a "PerStore"
		// struct for each store we're comparing.
		for _, f := range newStore {
			s := f(ctx, t).(datastore.IndexerV1)
			typ := reflect.ValueOf(s).Type().String()
			_, name, ok := strings.Cut(typ, ".")
			if !ok {
				t.Fatalf("wild name: %q", typ)
			}
			tcmp.perStore = append(tcmp.perStore, IndexerV1AffectedPerStore{
				store: s,
				name:  name,
			})
		}
		todo := []func(*testing.T){
			forEachStore(ctx, &tcmp, tcmp.LoadArtifacts),
			forEachStore(ctx, &tcmp, tcmp.IndexManifest),
			forEachStore(ctx, &tcmp, tcmp.AffectedManifests),
		}
		for _, sub := range todo {
			sub(t)
		}
	}
}

type IndexerV1AffectedCompare struct {
	Testcase *IndexerV1AffectedTest
	Archive  *txtar.Archive
	perStore []IndexerV1AffectedPerStore

	Fixture *Fixture
}

func (cmp *IndexerV1AffectedCompare) CmpOpts() cmp.Options                  { return affectedCmpopts }
func (cmp *IndexerV1AffectedCompare) PerStore() []IndexerV1AffectedPerStore { return cmp.perStore }

type IndexerV1AffectedPerStore struct {
	store datastore.IndexerV1
	name  string
}

func (per IndexerV1AffectedPerStore) Name() string               { return per.name }
func (per IndexerV1AffectedPerStore) Store() datastore.IndexerV1 { return per.store }

func (cmp *IndexerV1AffectedCompare) LoadArtifacts(ctx context.Context, t *testing.T, s datastore.IndexerV1) error {
	n := cmp.Testcase.Name
	_ = n
	return nil
}
func (cmp *IndexerV1AffectedCompare) IndexManifest(_ context.Context, t *testing.T, s datastore.IndexerV1) error {
	return nil
}
func (cmp *IndexerV1AffectedCompare) AffectedManifests(_ context.Context, t *testing.T, s datastore.IndexerV1) error {
	return nil
}

// AffectedCmpopts is the [cmp.Options] for [IndexerV1AffectedTest] tests.
var affectedCmpopts = cmp.Options{
	// Due to the Store returning the ref ID in this API, we need to
	// ignore the value; it will never match.
	//
	// Similar with "Date" -- it's a database timestamp.
	cmpopts.IgnoreFields(driver.UpdateOperation{}, "Ref", "Date"),
	// These IDs are also created database-side.
	cmpopts.IgnoreFields(claircore.Vulnerability{}, "ID", "Package.ID", "Dist.ID", "Repo.ID"),
}
