package rpm

import (
	"context"
	"io/fs"
	"path"

	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
)

func findDBs(ctx context.Context, out *[]foundDB, sys fs.FS) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		dir, n := path.Split(p)
		dir = path.Clean(dir)
		switch n {
		case `Packages`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			ok := bdb.CheckMagic(ctx, f)
			f.Close()
			if !ok {
				return nil
			}
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindBDB,
			})
		case `rpmdb.sqlite`:
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindSQLite,
			})
		case `Packages.db`:
			f, err := sys.Open(p)
			if err != nil {
				return err
			}
			ok := ndb.CheckMagic(ctx, f)
			f.Close()
			if !ok {
				return nil
			}
			*out = append(*out, foundDB{
				Path: dir,
				Kind: kindNDB,
			})
		}
		return nil
	}
}

type dbKind uint

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -linecomment -type dbKind

const (
	_ dbKind = iota

	kindBDB    // bdb
	kindSQLite // sqlite
	kindNDB    // ndb
)

type foundDB struct {
	Path string
	Kind dbKind
}

func (f foundDB) String() string {
	return f.Kind.String() + ":" + f.Path
}
