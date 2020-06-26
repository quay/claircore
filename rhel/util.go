package rhel

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"

	"github.com/quay/claircore"
)

// FilesByRegexp retrieves specific files from the layer's tar archive
// based on provided regexp.
//
// An error is returned only if none of the requested files are found.
func filesByRegexp(l *claircore.Layer, re *regexp.Regexp) (map[string]*bytes.Buffer, error) {
	// BUG(hank) The semantics of the internal filesByRegexp function may be
	// surprising:
	//
	// Paths have Clean called on them, but may still be absolute.
	//
	// Symlinks are not considered.
	//
	// Paths are considered as a string, with no special treatment of separators.
	r, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rs := r.(io.ReadSeeker)

	f := make(map[string]*bytes.Buffer)
	tr := tar.NewReader(rs)
	hdr, err := tr.Next()
	for ; err == nil; hdr, err = tr.Next() {
		name := filepath.Clean(hdr.Name)
		if !re.MatchString(name) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			b := make([]byte, hdr.Size)
			if n, err := io.ReadFull(tr, b); int64(n) != hdr.Size || err != nil {
				return nil, fmt.Errorf("rhel: unable to read file from archive: read %d bytes (wanted: %d): %w", n, hdr.Size, err)
			}
			f[name] = bytes.NewBuffer(b)
		default:
			// skip
		}
	}
	if err != io.EOF {
		return nil, err
	}

	// If there's nothing in the "f" map, we didn't find anything.
	if len(f) == 0 {
		return nil, claircore.ErrNotFound
	}
	return f, nil
}
