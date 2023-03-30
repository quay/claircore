package java

import (
	"context"
	"io/fs"
	"path"
	"strings"

	"github.com/quay/claircore/java/jar"
)

// Archives returns a slice of names that are probably archives, based on name
// and size. Callers should still check that the named file is valid.
func archives(ctx context.Context, sys fs.FS) (out []string, err error) {
	return out, fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		// Incoming checks:
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}

		// Name checks:
		switch ext := path.Ext(fi.Name()); {
		case ext == ".jar", ext == ".war", ext == ".ear": // OK
		case strings.HasPrefix(fi.Name(), ".wh."):
			return nil
		default:
			return nil
		}
		// Size check:
		if fi.Size() < jar.MinSize {
			return nil
		}

		// Probably an archive.
		out = append(out, p)
		return nil
	})
}
