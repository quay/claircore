package claircore

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Layer is a container image filesystem layer. Layers are stacked
// on top of each other to comprise the final filesystem of the container image.
type Layer struct {
	// Hash is a content addressable hash uniqely identifying this layer.
	// Libindex will treat layers with this same hash as identical.
	Hash    Digest              `json:"hash"`
	URI     string              `json:"uri"`
	Headers map[string][]string `json:"headers"`

	// path to local file containing uncompressed tar archive of the layer's content
	localPath string
}

func (l *Layer) SetLocal(f string) error {
	l.localPath = f
	return nil
}

func (l *Layer) Fetched() bool {
	_, err := os.Stat(l.localPath)
	return err == nil
}

// Reader returns a ReadCloser of the layer.
//
// It should also implement io.Seeker, and should be a tar stream.
func (l *Layer) Reader() (io.ReadCloser, error) {
	if l.localPath == "" {
		return nil, fmt.Errorf("claircore: Layer not fetched")
	}
	f, err := os.Open(l.localPath)
	if err != nil {
		return nil, fmt.Errorf("claircore: unable to open tar: %w", err)
	}
	return f, nil
}

// NormalizeIn is used to make sure paths are tar-root relative.
func normalizeIn(in, p string) string {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(in, p)
	}
	if filepath.IsAbs(p) {
		p = p[1:]
	}
	return p
}

// ErrNotFound is returned by Layer.Files if none of the requested files are
// found.
var ErrNotFound = errors.New("claircore: unable to find any requested files")

// Files retrieves specific files from the layer's tar archive.
//
// An error is returned only if none of the requested files are found.
//
// The returned map may contain more entries than the number of paths requested.
// All entries in the map are keyed by paths that are relative to the tar-root.
// For example, requesting paths of "/etc/os-release", "./etc/os-release", and
// "etc/os-release" will all result in any found content being stored with the
// key "etc/os-release".
func (l *Layer) Files(paths ...string) (map[string]*bytes.Buffer, error) {
	r, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rs := r.(io.ReadSeeker)

	// Clean the input paths.
	want := make(map[string]struct{})
	for i, p := range paths {
		p := normalizeIn("/", p)
		paths[i] = p
		want[p] = struct{}{}
	}

	alias := make(map[string]string)
	f := make(map[string]*bytes.Buffer)
	again := true // again is our flag for re-reading the tarball.
	for rs.Seek(0, io.SeekStart); again; rs.Seek(0, io.SeekStart) {
		again = false
		tr := tar.NewReader(rs)
		hdr, err := tr.Next()
		for ; err == nil; hdr, err = tr.Next() {
			name := filepath.Clean(hdr.Name)
			// check if the current header has a path name we are
			// searching for.
			if _, ok := want[name]; !ok {
				continue
			}
			delete(want, name)

			switch hdr.Typeflag {
			case tar.TypeLink, tar.TypeSymlink:
				n := normalizeIn(filepath.Join("/", filepath.Dir(name)), hdr.Linkname)
				if _, ok := f[n]; !ok { // If we don't already have it, add to the want set.
					want[n] = struct{}{}
					again = true
				}
				alias[name] = n
			case tar.TypeReg:
				b := make([]byte, hdr.Size)
				if n, err := io.ReadFull(tr, b); int64(n) != hdr.Size || err != nil {
					return nil, fmt.Errorf("claircore: unable to read file from archive: read %d bytes (wanted: %d): %w", n, hdr.Size, err)
				}
				f[name] = bytes.NewBuffer(b)
			default:
				// skip
			}
		}
		if err != io.EOF {
			return nil, err
		}
	}

	// Fixup the names from chasing symlinks.
	notfound := &bytes.Buffer{}
	for n := range want {
		// If the target is still in the want list, we didn't find it. So,
		// use the notfound sentinel.
		f[n] = notfound
	}
	for len(alias) != 0 {
		for from, to := range alias {
			f[from] = f[to]
			// Once we've chased any symlinks all the way through, remove them.
			if f[from] != nil {
				delete(alias, from)
			}
		}
	}
	// Now remove anything that's resolved to the notfound sentinel.
	for n, v := range f {
		if v == notfound {
			delete(f, n)
		}
	}

	// If there's nothing in the "f" map, we didn't find anything.
	if len(f) == 0 {
		return nil, ErrNotFound
	}
	return f, nil
}
