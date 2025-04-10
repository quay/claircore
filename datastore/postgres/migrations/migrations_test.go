package migrations

import (
	"bufio"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/remind101/migrate"
)

func TestBasicIndexerMigrations(t *testing.T) {
	testMigrations(t, "indexer", IndexerMigrations)
}

func TestBasicMatchMigrations(t *testing.T) {
	testMigrations(t, "matcher", MatcherMigrations)
}

func testMigrations(t *testing.T, root string, migrations []migrate.Migration) {
	var fileMigrations []string
	err := iofs.WalkDir(fs, root, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == root {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		if filepath.Ext(d.Name()) != ".sql" {
			return fmt.Errorf("%s is not a .sql file", path)
		}

		fileMigrations = append(fileMigrations, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(fileMigrations) != len(migrations) {
		t.Error(cmp.Diff(len(fileMigrations), len(migrations)))
	}

	for i, m := range migrations {
		if m.ID != i+1 {
			t.Error(cmp.Diff(m.ID, i+1))
		}
	}
}

func TestMigrationsMismatch(t *testing.T) {
	var migrations, files []string

	// Get referenced migrations
	migrationLine, err := regexp.Compile(`runFile\("(.*)"\)`)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("migrations.go")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		ms := migrationLine.FindSubmatch(s.Bytes())
		switch {
		case ms == nil, len(ms) == 1:
			continue
		case len(ms) == 2:
			migrations = append(migrations, filepath.Clean(string(ms[1])))
		}
	}
	if err := s.Err(); err != nil {
		t.Error(err)
	}
	slices.Sort(migrations)
	// Get migration files
	err = iofs.WalkDir(fs, ".", func(p string, d iofs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case filepath.Ext(d.Name()) != ".sql":
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		t.Error(err)
	}
	slices.Sort(files)

	// Check referenced files exist and existing files are referenced.
	if !cmp.Equal(migrations, files) {
		t.Log("error mismatch of migrations to entries:")
		t.Error(cmp.Diff(migrations, files))
	}
}
