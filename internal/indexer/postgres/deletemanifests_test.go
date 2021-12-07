package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

func TestDeleteManifests(t *testing.T) {
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	pool := TestDatabase(ctx, t)
	store := NewStore(pool)
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
}

var cmpOpts cmp.Option = cmp.Transformer("DigestTransformer", func(d claircore.Digest) string { return d.String() })
