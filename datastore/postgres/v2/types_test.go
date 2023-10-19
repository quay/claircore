package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/postgres/v2"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestTypes(t *testing.T) {
	t.Parallel()
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)
	cfg := postgres.TestMatcherDB(ctx, t)
	cfg.AfterConnect = connectRegisterTypes
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("UUID", func(t *testing.T) {
		id := uuid.New()
		t.Run("Value", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			var tgt uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT $1::uuid;`, id).Scan(&tgt); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(tgt, id) {
				t.Error(cmp.Diff(tgt, id))
			}
		})
		t.Run("Pointer", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			var tgt uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT $1::uuid;`, &id).Scan(&tgt); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(tgt, id) {
				t.Error(cmp.Diff(tgt, id))
			}
		})
		t.Run("Array", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			in := make([]uuid.UUID, 10)
			tgt := make([]uuid.UUID, 10)
			for i := range in {
				in[i] = uuid.New()
			}
			if err := pool.QueryRow(ctx, `SELECT $1::uuid[];`, in).Scan(&tgt); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(tgt, in) {
				t.Error(cmp.Diff(tgt, in))
			}
		})
	})

	t.Run("Version", func(t *testing.T) {
		v := claircore.Version{
			V: [10]int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
		}
		t.Run("Value", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			var tgt claircore.Version
			if err := pool.QueryRow(ctx, `SELECT $1::int4[];`, v).Scan(&tgt); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(tgt, v) {
				t.Error(cmp.Diff(tgt, v))
			}
		})
		t.Run("Pointer", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			var tgt claircore.Version
			if err := pool.QueryRow(ctx, `SELECT $1::int4[];`, &v).Scan(&tgt); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(tgt, v) {
				t.Error(cmp.Diff(tgt, v))
			}

			s := make([]int32, 10)
			if err := pool.QueryRow(ctx, `SELECT $1::int4[];`, &v).Scan(&s); err != nil {
				t.Error(err)
			}
		})
	})

	t.Run("VersionRange", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		r := claircore.Range{
			Lower: claircore.Version{
				V: [10]int32{0, 1},
			},
			Upper: claircore.Version{
				V: [10]int32{1, 1},
			},
		}
		var tgt claircore.Range
		if err := pool.QueryRow(ctx, `SELECT $1::VersionRange;`, &r).Scan(&tgt); err != nil {
			t.Error(err)
		}

		if !cmp.Equal(tgt, r) {
			t.Error(cmp.Diff(tgt, r))
		}
	})

	t.Run("CPE", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		var tgt cpe.WFN
		wfn, err := cpe.UnbindFS(someCPE)
		if err != nil {
			t.Fatal(err)
		}
		// CPEs are NULL-able TEXT columns, at least until we write a CPE type.
		if err := pool.QueryRow(ctx, `SELECT $1::text;`, &wfn).Scan(&tgt); err != nil {
			t.Error(err)
		}
		if !cmp.Equal(tgt, wfn) {
			t.Error(cmp.Diff(tgt, wfn))
		}
		t.Run("NULL", func(t *testing.T) {
			t.Run("Scan", func(t *testing.T) {
				t.Skip("TODO")
				ctx := zlog.Test(ctx, t)
				var tgt cpe.WFN
				if err := pool.QueryRow(ctx, `SELECT NULL;`).Scan(&tgt); err != nil {
					t.Error(err)
				}
			})
			t.Run("Encode", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				var wfn *cpe.WFN
				var tgt *cpe.WFN
				if err := pool.QueryRow(ctx, `SELECT $1::text;`, wfn).Scan(&tgt); err != nil {
					t.Error(err)
				}
			})
		})
	})

	t.Run("Distribution", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		var tgt claircore.Distribution
		d := claircore.Distribution{
			ID:              "1",
			Name:            "name",
			DID:             "did",
			Version:         "version",
			VersionCodeName: "version_code_name",
			VersionID:       "version_id",
			Arch:            "arch",
			CPE:             cpe.MustUnbind(someCPE),
			PrettyName:      "pretty_name",
		}
		if err := pool.QueryRow(ctx, `SELECT ROW(
			1::text, 
			'name'::text,
			'did'::text,
			'version'::text,
			'version_code_name'::text,
			'version_id'::text,
			'arch'::text,
			'`+someCPE+`'::text,
			'pretty_name'::text
			);`).Scan(&tgt); err != nil {
			t.Error(err)
		}
		if !cmp.Equal(tgt, d) {
			t.Error(cmp.Diff(tgt, d))
		}
	})

	t.Run("File", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		var tgt claircore.File
		f := claircore.File{
			Path: "dev/.wh.null",
			Kind: "whiteout",
		}
		if err := pool.QueryRow(ctx, `SELECT ROW('dev/.wh.null'::text, 'whiteout'::text);`).Scan(&tgt); err != nil {
			t.Error(err)
		}
		if !cmp.Equal(tgt, f) {
			t.Error(cmp.Diff(tgt, f))
		}
	})

	t.Run("Repository", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		var tgt claircore.Repository
		r := claircore.Repository{
			ID:   "1",
			Name: "name",
			Key:  "key",
			URI:  "uri",
			CPE:  cpe.MustUnbind(someCPE),
		}
		if err := pool.QueryRow(ctx, `SELECT ROW(
			1::text,
			'name'::text,
			'key'::text,
			'uri'::text,
			'`+someCPE+`'::text
			);`).Scan(&tgt); err != nil {
			t.Error(err)
		}
		if !cmp.Equal(tgt, r) {
			t.Error(cmp.Diff(tgt, r))
		}
	})
}
