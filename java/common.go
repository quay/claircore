package java

import (
	"context"
	"io/fs"
	"strings"

	"github.com/quay/claircore/java/jar"
)

// Archives returns a slice of names that are probably archives, based on name
// and size. Callers should still check that the named file is valid.
func archives(_ context.Context, sys fs.FS) (out []string, err error) {
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

		// Prefix check:
		if strings.HasPrefix(fi.Name(), ".wh.") {
			return nil
		}

		// Extension check:
		if !jar.ValidExt(fi.Name()) {
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
