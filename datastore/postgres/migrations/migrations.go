// Package migrations contains database migrations.
//
// It's expected that github.com/remind101/migrate will be used to apply these,
// but it's possible to do this manually if the user needs something specific.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/remind101/migrate"
)

// Canonical names for the table containing migration metadata.
const (
	IndexerMigrationTable = "libindex_migrations"
	MatcherMigrationTable = "libvuln_migrations"
)

// Slices containing the database migrations.
var (
	IndexerMigrations []migrate.Migration
	MatcherMigrations []migrate.Migration
)

func init() {
	IndexerMigrations = loadMigrations(`indexer`)
	MatcherMigrations = loadMigrations(`matcher`)
}

//go:embed */*.sql
var sys embed.FS

func loadMigrations(dir string) []migrate.Migration {
	ents, err := fs.ReadDir(sys, dir)
	if err != nil {
		panic(fmt.Errorf("programmer error: unable to read embed: %w", err))
	}

	ms := make([]migrate.Migration, 0, len(ents))
	id := 1
	for _, ent := range ents {
		if path.Ext(ent.Name()) != ".sql" {
			continue
		}
		if !ent.Type().IsRegular() {
			continue
		}

		p := path.Join(dir, ent.Name())
		ms = append(ms, migrate.Migration{
			ID: id,
			Up: func(tx *sql.Tx) error {
				f, err := sys.Open(p)
				if err != nil {
					return fmt.Errorf("unable to open migration %q: %v", p, err)
				}
				defer f.Close()
				var b strings.Builder
				if _, err := io.Copy(&b, f); err != nil {
					return fmt.Errorf("unable to read migration %q: %v", p, err)
				}
				if _, err := tx.Exec(b.String()); err != nil {
					return fmt.Errorf("unable to exec migration %q: %v", p, err)
				}
				return nil
			},
		})
		id++
	}

	return ms
}

//go:generate find . -name *.sql -exec go run github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest --language postgresql --fix {} ;
