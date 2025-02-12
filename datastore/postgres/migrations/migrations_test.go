package migrations

import (
	"bufio"
	iofs "io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMigrationsMismatch(t *testing.T) {
	var migrations, files []string

	// Get referenced migrations
	migrationLine, err := regexp.Compile(`runFile\(\"(.*)\"\)`)
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
			migrations = append(migrations, path.Clean(string(ms[1])))
		}
	}
	if err := s.Err(); err != nil {
		t.Error(err)
	}
	slices.Sort(migrations)

	// Get migration files
	err = iofs.WalkDir(os.DirFS("."), ".", func(p string, d iofs.DirEntry, err error) error {
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
