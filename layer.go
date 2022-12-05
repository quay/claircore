package claircore

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/toolkit/spool"
)

// Layer is a container image filesystem layer. Layers are stacked
// on top of each other to comprise the final filesystem of the container image.
type Layer struct {
	// Hash is a content addressable hash uniqely identifying this layer.
	// Libindex will treat layers with this same hash as identical.
	Hash    Digest              `json:"hash"`
	URI     string              `json:"uri"`
	Headers map[string][]string `json:"headers"`

	// File containing uncompressed tar archive of the layer's content.
	file *spool.File
}

func (l *Layer) SetLocal(f string) error {
	return errors.New("claircore: SetLocal unused")
}

// SetLayerFile associates a file with a layer.
//
// HACK(hank) This function exists to get used in the fetcher via linker tricks.
// This state of affairs should only exist until we get the chance to rework the
// Layer usages.
func setLayerFile(l *Layer, f *spool.File) error {
	l.file = f
	return nil
}

func (l *Layer) Fetched() bool {
	return l.file != nil
}

// Reader returns a ReadAtCloser of the layer.
//
// It should also implement io.Seeker, and should be a tar stream.
func (l *Layer) Reader() (ReadAtCloser, error) {
	return l.file.Reopen()
}

// ReadAtCloser is an io.ReadCloser and also an io.ReaderAt
type ReadAtCloser interface {
	io.ReadCloser
	io.ReaderAt
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
//
// Deprecated: Callers should instead use `pkg/tarfs` and the `io/fs` package.
func (l *Layer) Files(paths ...string) (map[string]*bytes.Buffer, error) {
	r, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, err
	}

	// Clean the input paths.
	want := make(map[string]struct{})
	for i, p := range paths {
		p := normalizeIn("/", p)
		paths[i] = p
		want[p] = struct{}{}
	}

	f := make(map[string]*bytes.Buffer)
	// Walk the fs. ReadFile will handle symlink resolution.
	if err := fs.WalkDir(sys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}
		if _, ok := want[p]; !ok {
			return nil
		}
		delete(want, p)
		b, err := fs.ReadFile(sys, p)
		if err != nil {
			return err
		}
		f[p] = bytes.NewBuffer(b)
		return nil
	}); err != nil {
		return nil, err
	}

	// If there's nothing in the "f" map, we didn't find anything.
	if len(f) == 0 {
		return nil, ErrNotFound
	}
	return f, nil
}
