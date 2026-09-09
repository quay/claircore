package migrations

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// These are the tables used to track migrations.
//
// Deprecated: use the [Indexer] and [Matcher] functions.
var (
	IndexerMigrationTable = pgx.Identifier{"libindex_migrations"}
	MatcherMigrationTable = pgx.Identifier{"libvuln_migrations"}
)

// Indexer runs migrations for an indexer database using the provided
// configuration.
func Indexer(ctx context.Context, cfg *pgx.ConnConfig) error {
	sys, err := fs.Sub(sys, "indexer")
	if err != nil {
		return fmt.Errorf("programmer error: %w", err)
	}
	return runMigrations(ctx, cfg, IndexerMigrationTable, sys)
}

// Matcher runs migrations for a matcher database using the provided
// configuration.
func Matcher(ctx context.Context, cfg *pgx.ConnConfig) error {
	sys, err := fs.Sub(sys, "matcher")
	if err != nil {
		return fmt.Errorf("programmer error: %w", err)
	}
	return runMigrations(ctx, cfg, MatcherMigrationTable, sys)
}

// MigrationFunc is the interface for application-driven migrations.
type MigrationFunc func(context.Context, *pgx.Conn) error

// IndexerFinishMigration will execute [MigrationFunc]s for any unfinished
// application-driven migrations.
func IndexerFinishMigration(ctx context.Context, cfg *pgx.ConnConfig, migrator func(id int) MigrationFunc) error {
	return runFinishMigrations(ctx, cfg, IndexerMigrationTable, migrator)
}

// MatcherFinishMigration will execute [MigrationFunc]s for any unfinished
// application-driven migrations.
func MatcherFinishMigration(ctx context.Context, cfg *pgx.ConnConfig, migrator func(id int) MigrationFunc) error {
	return runFinishMigrations(ctx, cfg, MatcherMigrationTable, migrator)
}

var (
	//go:embed query/create_table.sql
	queryCreateTable string
	//go:embed query/check_migration.sql
	queryCheckMigration string
	//go:embed query/start_migration.sql
	queryStartMigration string
	//go:embed query/finish_migration.sql
	queryFinishMigration string
	//go:embed query/wait_lock.sql
	queryWaitLock string
	//go:embed query/try_lock.sql
	queryTryLock string
	//go:embed query/find_app_migration.sql
	queryFindAppMigration string
)

// Migration is a description of a database migration.
type migration struct {
	ID    int
	Name  string
	Start bool
}

// NewMigration creates a migration value for the given name.
//
// This function panics on error because it is intended to only be used with the
// embedded filesystem. If that is malformed, it's panic worthy.
func newMigration(name string) migration {
	n, _, ok := strings.Cut(name, "-")
	if !ok {
		panic(fmt.Sprintf("bad name format: %q", name))
	}
	id, err := strconv.Atoi(n)
	if err != nil {
		panic(fmt.Sprintf("bad name format: %s: %v", name, err))
	}
	return migration{
		ID:    id,
		Name:  name,
		Start: strings.HasSuffix(name, `.start.sql`),
	}
}

var (
	runMigrationsKey       = crc32.ChecksumIEEE([]byte("migrations"))
	runFinishMigrationsKey = crc32.ChecksumIEEE([]byte("finish_migrations"))
)

// RunMigrations does what it says on the tin.
func runMigrations(ctx context.Context, cfg *pgx.ConnConfig, table pgx.Identifier, sys fs.FS) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}
	defer conn.Close(ctx)
	rw := tableRewriter(table)

	// Advisory lock is dropped when the connection (session) is closed.
	if _, err := conn.Exec(ctx, queryWaitLock, runMigrationsKey); err != nil {
		return fmt.Errorf("unable to obtain migration lock %x: %w", runMigrationsKey, err)
	}
	if _, err := conn.Exec(ctx, queryCreateTable, rw); err != nil {
		return fmt.Errorf("unable to create migration table %s: %w", table.Sanitize(), err)
	}

	ents, err := fs.ReadDir(sys, ".")
	if err != nil {
		panic("programmer error: unable to readdir")
	}
	ms := func(yield func(migration) bool) {
		for _, ent := range ents {
			if !yield(newMigration(ent.Name())) {
				return
			}
		}
	}

	for m := range ms {
		b, err := fs.ReadFile(sys, m.Name)
		if err != nil {
			return fmt.Errorf("failed to perform migrations: %w", err)
		}

		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			var ok bool
			err := tx.QueryRow(ctx, queryCheckMigration, rw, m.ID).Scan(&ok)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}

			if _, err := tx.Exec(ctx, queryStartMigration, rw, m.ID, m.Start); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(b)); err != nil {
				return err
			}
			if !m.Start {
				if _, err := tx.Exec(ctx, queryFinishMigration, rw, m.ID); err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to perform migrations: %w", err)
		}
	}

	return nil
}

// RunFinishMigrations does what it says on the tin.
func runFinishMigrations(ctx context.Context, cfg *pgx.ConnConfig, table pgx.Identifier, get func(int) MigrationFunc) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}
	defer conn.Close(ctx)
	rw := tableRewriter(table)

	var ok bool
	err = conn.QueryRow(ctx, queryTryLock, runFinishMigrationsKey).Scan(&ok)
	if err != nil {
		return fmt.Errorf("unable to attempt lock: %w", err)
	}
	if !ok {
		return nil
	}

	rows, err := conn.Query(ctx, queryFindAppMigration, rw)
	if err != nil {
		return fmt.Errorf("unable to query rows: %w", err)
	}
	ids, err := pgx.CollectRows[int](rows, pgx.RowTo)
	if err != nil {
		return fmt.Errorf("error reading rows: %w", err)
	}
	for _, id := range ids {
		// Out of an abundance of caution, obtain a fresh connection for each migration.
		//
		// This allows for any session state to be cleaned up uniformly every time.
		err := func() error {
			m := get(id)
			if m == nil {
				return errors.New("no migration supplied")
			}
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				return fmt.Errorf("unable to connect to database: %w", err)
			}
			defer conn.Close(ctx)

			if err := m(ctx, conn); err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return fmt.Errorf("error running application work for migration #%02d: %w", id, err)
		}

		if _, err := conn.Exec(ctx, queryFinishMigration, rw, id); err != nil {
			return fmt.Errorf("unable to mark migration #%02d done: %w", id, err)
		}
	}

	return nil
}

//go:generate find . -name *.sql -exec go run github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest --language postgresql --fix {} ;
//go:embed */*.sql
var sys embed.FS

// IndexerMigrations returns the state of migrations for the connected database.
func IndexerMigrations(ctx context.Context, conn *pgx.Conn) (*Migrations, error) {
	return getMigrations(ctx, conn, IndexerMigrationTable)
}

// MatcherMigrations returns the state of migrations for the connected database.
func MatcherMigrations(ctx context.Context, conn *pgx.Conn) (*Migrations, error) {
	return getMigrations(ctx, conn, MatcherMigrationTable)
}

// Migrations is the state of migrations for a database.
type Migrations struct {
	state []migrationState
}

type migrationState struct {
	ID       int
	Created  time.Time
	Finished time.Time
	App      bool
}

// ID reports if the migration with the given ID exists and if it is determined
// to be "done".
func (m *Migrations) ID(id int) (exists bool, done bool) {
	idx, ok := slices.BinarySearchFunc(m.state, id, func(s migrationState, id int) int {
		return cmp.Compare(s.ID, id)
	})
	if ok {
		s := &m.state[idx]
		return true, s.App == false || !s.Finished.IsZero()
	}
	return false, false
}

// AnyActive reports if there are any active application-driven migrations.
//
// If there are, the application should arrange to poll the migration states in
// the future.
func (m *Migrations) AnyActive() bool {
	return slices.ContainsFunc(m.state, func(s migrationState) bool {
		return s.App && s.Finished.IsZero()
	})
}

//go:embed query/select_migrations.sql
var querySelectMigrations string

// GetMigrations does what it says on the tin.
func getMigrations(ctx context.Context, conn *pgx.Conn, table pgx.Identifier) (*Migrations, error) {
	rw := tableRewriter(table)

	rows, err := conn.Query(ctx, querySelectMigrations, rw)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations: %w", err)
	}
	feature, err := pgx.CollectRows(rows, pgx.RowToStructByPos[migrationState])

	return &Migrations{
		state: feature,
	}, nil
}
