package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres/v2"
)

func TestQueryMetadata(t *testing.T) {
	var want []string
	fs.WalkDir(queries, "queries", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if path.Ext(d.Name()) != ".sql" {
			return nil
		}
		want = append(want, strings.TrimPrefix(p, "queries/"))
		return nil
	})

	for _, w := range want {
		if _, exists := queryMetadata.Table[w]; !exists {
			t.Errorf("query %s: missing %s", w, "table")
		}
		if _, exists := queryMetadata.Op[w]; !exists {
			t.Errorf("query %s: missing %s", w, "operation")
		}
	}
	if t.Failed() {
		t.Logf("regenerate the query metadata: %q", `go generate -run querymeta`)
	}

	for f := range explainExceptions {
		_, err := os.Stat(filepath.Join("queries", f))
		if err != nil {
			t.Error(err)
		}
	}
}

func TestExplain(t *testing.T) {
	integration.NeedDB(t)
	t.Run("Indexer", explainInner)
	t.Run("Matcher", explainInner)
}

func explainInner(t *testing.T) {
	dir := strings.ToLower(path.Base(t.Name()))
	ctx := zlog.Test(context.Background(), t)
	var cfg *pgxpool.Config
	switch dir {
	case "indexer":
		cfg = pgtest.TestIndexerDB(ctx, t)
	case "matcher":
		cfg = pgtest.TestMatcherDB(ctx, t)
	default:
		t.Fatalf("unknown subsystem: %q", dir)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	ents, err := fs.ReadDir(queries, path.Join("queries", dir))
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		t.Skipf("no directory for %q", dir)
	default:
		t.Fatal(err)
	}

	for _, ent := range ents {
		p := path.Join(dir, ent.Name())
		t.Run(path.Base(p), func(t *testing.T) {
			var out string
			q := loadQuery(ctx, p)
			t.Log("query:")
			t.Log(queryPretty.ReplaceAllString(q, " "))
			switch queryMetadata.Op[p] {
			case "REFRESH MATERIALIZED VIEW":
				t.Skip("utility function, skipping")
			}
			err := pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
				conn := c.Conn()
				q := `EXPLAIN (FORMAT JSON) ` + q
				desc, err := conn.Prepare(ctx, t.Name(), q)
				if err != nil {
					return err
				}
				args := make([]interface{}, len(desc.ParamOIDs))
				// Add some bogus values to actually exercise the planner.
				for i, oid := range desc.ParamOIDs {
					switch oid {
					case pgtype.TextOID:
						args[i] = "SOMESTRING"
					case pgtype.TextArrayOID:
						s := make([]string, 10)
						for n := range s {
							s[n] = strconv.Itoa(n)
						}
						args[i] = s
					}
				}
				return conn.QueryRow(ctx, t.Name(), args...).Scan(&out)
			})
			if err != nil {
				t.Fatal(err)
			}
			var exp []explainQuery
			if err := json.Unmarshal([]byte(out), &exp); err != nil {
				t.Logf("got: %q", out)
				t.Fatal(err)
			}
			for i, q := range exp {
				walkPlan(t, explainExceptions[p], fmt.Sprintf("%d.Plan", i), &q.Plan)
			}
			t.Log("explain out:")
			t.Log(out)
		})
	}

}

var (
	queryPretty = regexp.MustCompile("\n\t*")
	// We might need exceptions, so this is a map of query path -> node paths ->
	// reason.
	explainExceptions = map[string]map[string]string{
		/*
			"subsystem/example_query.sql": {
				"0.Plan.0.Plans.1": "usage validated to be over a trivial number of rows",
			},
		*/
		"matcher/initialized_initialized.sql": {
			"0.Plan.Plans.0": "only reads a single row",
		},
		"matcher/gc_distinct.sql": {
			"0.Plan.Plans.0": "TODO",
		},
		"matcher/getlatestupdaterefs_any.sql": {
			"0.Plan.Plans.0.Plans.0": "TODO",
		},
		"matcher/getupdateoperations_getupdaters.sql": {
			"0.Plan.Plans.0": "TODO",
		},
		"matcher/getupdatediff_load.sql": {
			"0.Plan.Plans.4": "TODO",
		},
		"matcher/recordupdatersetstatus_update.sql": {
			"0.Plan.Plans.0": "TODO",
		},
	}
)

type explainQuery struct {
	Plan explainPlan
}

type explainPlan struct {
	Kind  string `json:"Node Type"`
	Plans []explainPlan
}

func walkPlan(t *testing.T, ok map[string]string, path string, p *explainPlan) {
	t.Helper()
	if p.Kind == "Seq Scan" {
		t.Logf("plan at %q invokes sequence scan", path)
		if reason, ok := ok[path]; ok {
			t.Logf("plan allowed: %s", reason)
		} else {
			t.Fail()
		}
	}
	for i := range p.Plans {
		walkPlan(t, ok, fmt.Sprintf("%s.Plans.%d", path, i), &p.Plans[i])
	}
}
