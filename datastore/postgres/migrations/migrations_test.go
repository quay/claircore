package migrations

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/test/integration"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

func TestApply(t *testing.T) {
	integration.NeedDB(t)
	t.Run("Matcher", runMigration(Matcher))
	t.Run("Indexer", runMigration(Indexer))
}

func runMigration(f func(context.Context, *pgx.ConnConfig) error) func(*testing.T) {
	return func(t *testing.T) {
		ctx := test.Logging(t)
		db, err := integration.NewDB(ctx, t)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close(ctx, t)

		poolcfg := db.Config()
		cfg := poolcfg.ConnConfig
		if err := f(ctx, cfg); err != nil {
			t.Fatal(err)
		}

		pool, err := pgxpool.NewWithConfig(ctx, poolcfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		which := path.Base(t.Name())
		t.Run("Schema", checkSchema(which, cfg))
	}
}

func checkSchema(which string, cfg *pgx.ConnConfig) func(*testing.T) {
	return func(t *testing.T) {
		ctx := test.Logging(t)
		if _, err := exec.LookPath("pg_dump"); err != nil {
			t.Skipf("skipping schema check: %v", err)
		}

		var out, buf bytes.Buffer
		cmd := exec.CommandContext(ctx, "pg_dump", "--format=plain", "--no-owner", "--schema-only")
		cmd.Env = append(
			os.Environ(),
			fmt.Sprintf("PGHOST=%s", cfg.Host),
			fmt.Sprintf("PGPORT=%d", cfg.Port),
			fmt.Sprintf("PGDATABASE=%s", cfg.Database),
			fmt.Sprintf("PGUSER=%s", cfg.User),
			fmt.Sprintf("PGPASSWORD=%s", cfg.Password),
		)
		cmd.Stdout = &buf
		cmd.Stderr = t.Output()
		if err := cmd.Run(); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(&out, "// # %s Schema\n//\n", which)
		nls := false
		first := true
	Read:
		for {
			l, err := buf.ReadString('\n')
			switch {
			case err == nil:
			case errors.Is(err, io.EOF):
				break Read
			default:
				t.Fatal(err)
			}
			l = strings.TrimRight(l, " \t\n")
			switch {
			case len(l) == 0 && first:
				continue
			case len(l) == 0 && !nls:
				nls = true
			case len(l) == 0 && nls,
				strings.HasPrefix(l, `--`),
				strings.HasPrefix(l, `\`),
				strings.HasPrefix(l, `SE`):
				continue
			case len(l) != 0:
				first = false
				nls = false
			}
			out.WriteString("//")
			if len(l) != 0 {
				out.WriteString("\t")
			}
			out.WriteString(l)
			out.WriteString("\n")
		}
		out.Truncate(out.Len() - 3)
		out.WriteString("package migrations\n")

		fn := strings.ToLower(which) + "_doc.go"

		want := out.String()
		got, err := os.ReadFile(fn)
		if err != nil {
			t.Error(err)
		}
		if got := string(got); got != want {
			t.Error(cmp.Diff(got, want, cmpopts.AcyclicTransformer("SplitLines", func(s string) []string {
				return strings.Split(s, "\n")
			})))
			t.Log("To update this test, re-run with `-artifacts` and copy the generated files out:")
			t.Log("\tgo test -artifacts || cp _artifacts/datastore/postgres/migrations/TestApply__*/*/*_doc.go ./")
		}

		if t.Failed() {
			err := os.WriteFile(filepath.Join(t.ArtifactDir(), fn), out.Bytes(), 0o666)
			if err != nil {
				t.Error(err)
			}
		}
	}
}
