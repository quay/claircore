package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestDeleteManifests(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := pgtest.TestIndexerDB(ctx, t)
	store := NewIndexerStore(pool)
	defer store.Close(ctx)

	t.Run("Nonexistent", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		in := []claircore.Digest{
			test.RandomSHA256Digest(t),
		}
		got, err := store.DeleteManifests(ctx, in...)
		if err != nil {
			t.Error(err)
		}
		if len(got) != 0 {
			t.Error(cmp.Diff(got, []claircore.Digest{}, cmpOpts))
		}
	})
	t.Run("NonexistentMulti", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		in := []claircore.Digest{
			test.RandomSHA256Digest(t),
			test.RandomSHA256Digest(t),
			test.RandomSHA256Digest(t),
			test.RandomSHA256Digest(t),
			test.RandomSHA256Digest(t),
		}
		got, err := store.DeleteManifests(ctx, in...)
		if err != nil {
			t.Error(err)
		}
		if len(got) != 0 {
			t.Error(cmp.Diff(got, []claircore.Digest{}, cmpOpts))
		}
	})
	const insertManifest = `INSERT INTO manifest (hash) SELECT unnest($1::TEXT[]);`
	t.Run("One", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		want := []claircore.Digest{
			test.RandomSHA256Digest(t),
		}
		if _, err := pool.Exec(ctx, insertManifest, digestSlice(want)); err != nil {
			t.Error(err)
		}
		got, err := store.DeleteManifests(ctx, want...)
		if err != nil {
			t.Error(err)
		}
		if !cmp.Equal(got, want, cmpOpts) {
			t.Error(cmp.Diff(got, want, cmpOpts))
		}
	})
	t.Run("Subset", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		in := make([]claircore.Digest, 8)
		for i := range in {
			in[i] = test.RandomSHA256Digest(t)
		}
		if _, err := pool.Exec(ctx, insertManifest, digestSlice(in)); err != nil {
			t.Error(err)
		}
		for _, want := range [][]claircore.Digest{in[:4], in[4:]} {
			arg := append(want[:len(want):len(want)], test.RandomSHA256Digest(t), test.RandomSHA256Digest(t))
			got, err := store.DeleteManifests(ctx, arg...)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, want, cmpOpts) {
				t.Error(cmp.Diff(got, want, cmpOpts))
			}
		}
	})
	const (
		insertLayers = `INSERT INTO layer (hash) SELECT unnest($1::TEXT[]);`
		assoc        = `WITH
	l AS (SELECT id FROM layer WHERE hash = ANY($1::TEXT[])),
	m AS (SELECT id FROM manifest WHERE hash = $2::TEXT)
INSERT INTO manifest_layer (i, manifest_id, layer_id)
	SELECT ROW_NUMBER() OVER (), m.id, l.id FROM m, l;`
	)
	t.Run("Layers", func(t *testing.T) {
		const (
			nManifests = 8
			layersPer  = 4
		)
		ctx := zlog.Test(ctx, t)
		ms := make([]claircore.Digest, nManifests)
		for i := range ms {
			ms[i] = test.RandomSHA256Digest(t)
		}
		ls := make([]claircore.Digest, nManifests+layersPer-1)
		for i := range ls {
			ls[i] = test.RandomSHA256Digest(t)
		}

		if _, err := pool.Exec(ctx, insertManifest, digestSlice(ms)); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(ctx, insertLayers, digestSlice(ls)); err != nil {
			t.Error(err)
		}
		var nLayers int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM layer;`).Scan(&nLayers); err != nil {
			t.Error(err)
		}
		for i, m := range ms {
			tag, err := pool.Exec(ctx, assoc, digestSlice(ls[i:i+layersPer]), m)
			t.Logf("affected: %d", tag.RowsAffected())
			if err != nil {
				t.Error(err)
			}
		}

		prev := len(ls)
		for _, m := range ms {
			want := []claircore.Digest{m}
			got, err := store.DeleteManifests(ctx, want...)
			if err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, want, cmpOpts) {
				t.Error(cmp.Diff(got, want, cmpOpts))
			}
			var rem int
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM layer;`).Scan(&rem); err != nil {
				t.Error(err)
			}
			if got, want := rem, prev; got >= want {
				t.Errorf("left overlayers: got: == %d, < want %d", got, want)
			}
			prev = rem
		}

		var rem int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM layer;`).Scan(&rem); err != nil {
			t.Error(err)
		}
		if got, want := rem, 0; got != want {
			t.Errorf("left overlayers: got: %d, want %d", got, want)
		}
	})

	t.Run("Manifest index", func(t *testing.T) {
		const (
			layersN    = 4
			manifestsN = 100
			packageN   = 10
		)
		s := NewIndexerStore(pool)
		ctx := zlog.Test(ctx, t)
		toDelete := make([]claircore.Digest, manifestsN)
		for i := 0; i < manifestsN; i++ {
			ir := &claircore.IndexReport{}
			ir.Hash = test.RandomSHA256Digest(t)
			toDelete[i] = ir.Hash
			ls := make([]claircore.Digest, layersN)
			for i := range ls {
				ls[i] = test.RandomSHA256Digest(t)
			}

			if _, err := pool.Exec(ctx, insertManifest, []claircore.Digest{ir.Hash}); err != nil {
				t.Error(err)
			}
			if _, err := pool.Exec(ctx, insertLayers, digestSlice(ls)); err != nil {
				t.Error(err)
			}
			var nLayers int
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM layer;`).Scan(&nLayers); err != nil {
				t.Error(err)
			}
			tag, err := pool.Exec(ctx, assoc, digestSlice(ls), ir.Hash)
			t.Logf("affected: %d", tag.RowsAffected())
			if err != nil {
				t.Error(err)
			}

			scnr := indexer.NewPackageScannerMock("mock", "1", "vulnerability")
			if err := s.RegisterScanners(ctx, indexer.VersionedScanners{scnr}); err != nil {
				t.Error(err)
			}

			pkgs := test.GenUniquePackages(packageN)
			layer := &claircore.Layer{Hash: ls[0]}
			if err := s.IndexPackages(ctx, pkgs, layer, scnr); err != nil {
				t.Error(err)
			}
			// Retrieve packages from DB so they are all correctly ID'd
			if pkgs, err = s.PackagesByLayer(ctx, layer.Hash, []indexer.VersionedScanner{scnr}); err != nil {
				t.Error(err)
			}

			pkgMap := make(map[string]*claircore.Package, packageN)
			envs := make(map[string][]*claircore.Environment, packageN)
			for _, p := range pkgs {
				pkgMap[p.ID] = p
				envs[p.ID] = []*claircore.Environment{
					{
						PackageDB:      "pdb",
						IntroducedIn:   ls[0],
						DistributionID: "d",
						RepositoryIDs:  []string{},
					},
				}
			}
			ir.Packages = pkgMap
			ir.Environments = envs

			if err := s.IndexManifest(ctx, ir); err != nil {
				t.Error(err)
			}
		}
		got, err := store.DeleteManifests(ctx, toDelete...)
		if err != nil {
			t.Error(err)
		}
		if len(got) != manifestsN {
			t.Error(cmp.Diff(got, toDelete, cmpOpts))
		}
	})
}

var cmpOpts cmp.Option = cmp.Transformer("DigestTransformer", func(d claircore.Digest) string { return d.String() })
