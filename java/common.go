package java

import (
	"context"
	"io/fs"
	"iter"
	"path"
	"strings"

	"github.com/quay/claircore/java/jar"
)

const (
	cdxJSON   = ".cdx.json"
	cdxJSONGZ = ".cdx.json.gz"
)

// WalkInteresting walks the [fs.FS] and reports interesting files:
//
//   - Archives: Names that are probably archives, based on name and size.
//   - SBoMs: Names that are probably CycloneDX SBoMs, either gzip compressed or not.
//
// Callers still need to perform validity checks in both cases.
func walkInteresting(ctx context.Context, sys fs.FS) (iter.Seq2[fileKind, string], func() error) {
	var err error
	seq := func(yield func(fileKind, string) bool) {
		err = fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir():
				return nil
			}
			n := path.Base(p)
			if strings.HasPrefix(n, ".wh.") {
				return nil
			}

			var k fileKind
			switch {
			case jar.ValidExt(n):
				fi, err := d.Info()
				if err != nil {
					return err
				}
				if fi.Size() < jar.MinSize {
					return nil
				}
				// Probably an archive.
				k = fileJAR
			case strings.HasSuffix(n, cdxJSON), strings.HasSuffix(n, cdxJSONGZ):
				k = fileSBoM
			default:
				return nil
			}

			if !yield(k, p) {
				return fs.SkipAll
			}
			return nil
		})
	}
	return seq, func() error { return err }
}

type fileKind uint

const (
	_ fileKind = iota
	fileSBoM
	fileJAR
)
