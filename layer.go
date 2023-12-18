package claircore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/quay/claircore/pkg/tarfs"
)

// LayerDescription is a description of a container layer. It should contain
// enough information to fetch the layer.
//
// Unlike the [Layer] type, this type does not have any extra state or access to
// the contents of the layer.
type LayerDescription struct {
	// Digest is a content addressable checksum uniquely identifying this layer.
	Digest string
	// URI is a URI that can be used to fetch layer contents.
	URI string
	// MediaType is the [OCI Layer media type] for this layer. Any [Indexer]
	// instance will support the OCI-defined media types, and may support others
	// based on its configuration.
	//
	// [OCI Layer media type]: https://github.com/opencontainers/image-spec/blob/main/layer.md
	MediaType string
	// Headers is additional request headers for fetching layer contents.
	Headers map[string][]string
}

// Layer is an internal representation of a container image file system layer.
// Layers are stacked on top of each other to create the final file system of
// the container image.
//
// This type being in the external API of the
// [github.com/quay/claircore/libindex.Libindex] type is a historical accident.
//
// Previously, it was OK to use Layer literals. This is no longer allowed and
// the [Layer.Init] method must be called. Any methods besides [Layer.Init]
// called on an uninitialized Layer will report errors and may panic.
type Layer struct {
	noCopy noCopy
	// Final is used to implement the panicking Finalizer.
	//
	// Without a unique allocation, we cannot set a Finalizer (so, when filling
	// in a Layer in a slice). A pointer to a zero-sized type (like a *struct{})
	// is not unique. So this camps on a unique heap allocation made for the
	// purpose of tracking the Closed state of this Layer.
	final *string

	// Hash is a content addressable hash uniquely identifying this layer.
	// Libindex will treat layers with this same hash as identical.
	Hash Digest `json:"hash"`
	// URI is a URI that can be used to fetch layer contents.
	//
	// Deprecated: This is exported for historical reasons and may stop being
	// populated in the future.
	URI string `json:"uri"`
	// Headers is additional request headers for fetching layer contents.
	//
	// Deprecated: This is exported for historical reasons and may stop being
	// populated in the future.
	Headers map[string][]string `json:"headers"`

	cleanup []io.Closer
	sys     fs.FS
	rd      io.ReaderAt
	closed  bool // Used to catch double-closes.
	init    bool // Used to track initialization.
}

// Init initializes a Layer in-place. This is provided for flexibility when
// constructing a slice of Layers.
func (l *Layer) Init(ctx context.Context, desc *LayerDescription, r io.ReaderAt) error {
	if l.init {
		return fmt.Errorf("claircore: Init called on already initialized Layer")
	}
	var err error
	l.Hash, err = ParseDigest(desc.Digest)
	if err != nil {
		return err
	}
	l.URI = desc.URI
	l.Headers = desc.Headers
	l.rd = r
	defer func() {
		if l.init {
			return
		}
		for _, f := range l.cleanup {
			f.Close()
		}
	}()

	switch desc.MediaType {
	case `application/vnd.oci.image.layer.v1.tar`,
		`application/vnd.oci.image.layer.v1.tar+gzip`,
		`application/vnd.oci.image.layer.v1.tar+zstd`,
		`application/vnd.oci.image.layer.nondistributable.v1.tar`,
		`application/vnd.oci.image.layer.nondistributable.v1.tar+gzip`,
		`application/vnd.oci.image.layer.nondistributable.v1.tar+zstd`:
		sys, err := tarfs.New(r)
		switch {
		case errors.Is(err, nil):
		default:
			return fmt.Errorf("claircore: layer %v: unable to create fs.FS: %w", desc.Digest, err)
		}
		l.sys = sys
	default:
		return fmt.Errorf("claircore: layer %v: unknown MediaType %q", desc.Digest, desc.MediaType)
	}

	_, file, line, _ := runtime.Caller(1)
	fmsg := fmt.Sprintf("%s:%d: Layer not closed", file, line)
	l.final = &fmsg
	runtime.SetFinalizer(l.final, func(msg *string) { panic(*msg) })
	l.init = true
	return nil
}

// Close releases held resources by this Layer.
//
// Not calling Close may cause the program to panic.
func (l *Layer) Close() error {
	if !l.init {
		return errors.New("claircore: Close: uninitialized Layer")
	}
	if l.closed {
		_, file, line, _ := runtime.Caller(1)
		panic(fmt.Sprintf("%s:%d: Layer closed twice", file, line))
	}
	runtime.SetFinalizer(l.final, nil)
	l.closed = true
	errs := make([]error, len(l.cleanup))
	for i, c := range l.cleanup {
		errs[i] = c.Close()
	}
	return errors.Join(errs...)
}

// SetLocal is a namespacing wart.
//
// Deprecated: This function unconditionally errors and does nothing. Use the
// [Layer.Init] method instead.
func (l *Layer) SetLocal(_ string) error {
	// TODO(hank) Just wrap errors.ErrUnsupported when updating to go1.21
	return errUnsupported
}

type unsupported struct{}

var errUnsupported = &unsupported{}

func (*unsupported) Error() string {
	return "unsupported operation"
}
func (*unsupported) Is(tgt error) bool {
	// Hack for forwards compatibility: In go1.21, [errors.ErrUnsupported] was
	// added and ideally we'd just use that. However, we're supporting go1.20
	// until it's out of upstream support. This hack will make constructions
	// like:
	//
	//	errors.Is(err, errors.ErrUnsupported)
	//
	// work as soon as a main module is built with go1.21.
	return tgt.Error() == "unsupported operation"
}

// Fetched reports whether the layer blob has been fetched locally.
//
// Deprecated: Layers should now only be constructed by the code that does the
// fetching. That is, merely having a valid Layer indicates that the blob has
// been fetched.
func (l *Layer) Fetched() bool {
	return l.init
}

// FS returns an [fs.FS] reading from an initialized layer.
func (l *Layer) FS() (fs.FS, error) {
	if !l.init {
		return nil, errors.New("claircore: unable to return FS: uninitialized Layer")
	}
	return l.sys, nil
}

// Reader returns a [ReadAtCloser] of the layer.
//
// It should also implement [io.Seeker], and should be a tar stream.
func (l *Layer) Reader() (ReadAtCloser, error) {
	if !l.init {
		return nil, errors.New("claircore: unable to return Reader: uninitialized Layer")
	}
	// Some hacks for making the returned ReadAtCloser implements as many
	// interfaces as possible.
	switch rd := l.rd.(type) {
	case *os.File:
		fi, err := rd.Stat()
		if err != nil {
			return nil, fmt.Errorf("claircore: unable to stat file: %w", err)
		}
		return &fileAdapter{
			SectionReader: io.NewSectionReader(rd, 0, fi.Size()),
			File:          rd,
		}, nil
	default:
	}
	// Doing this with no size breaks the "seek to the end trick".
	//
	// This could do additional interface testing to support the various sizing
	// tricks we do elsewhere.
	return &rac{io.NewSectionReader(l.rd, 0, -1)}, nil
}

// Rac implements [io.Closer] on an [io.SectionReader].
type rac struct {
	*io.SectionReader
}

// Close implements [io.Closer].
func (*rac) Close() error {
	return nil
}

// FileAdapter implements [ReadAtCloser] in such a way that most of the File's
// methods are promoted, but the [io.ReaderAt] and [io.ReadSeeker] interfaces
// are dispatched to the [io.SectionReader] so that there's an independent
// cursor.
type fileAdapter struct {
	*io.SectionReader
	*os.File
}

// Read implements [io.Reader].
func (a *fileAdapter) Read(p []byte) (n int, err error) {
	return a.SectionReader.Read(p)
}

// ReadAt implements [io.ReaderAt].
func (a *fileAdapter) ReadAt(p []byte, off int64) (n int, err error) {
	return a.SectionReader.ReadAt(p, off)
}

// Seek implements [io.Seeker].
func (a *fileAdapter) Seek(offset int64, whence int) (int64, error) {
	return a.SectionReader.Seek(offset, whence)
}

// Close implements [io.Closer].
func (*fileAdapter) Close() error {
	return nil
}

// ReadAtCloser is an [io.ReadCloser] and also an [io.ReaderAt].
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

// ErrNotFound is returned by [Layer.Files] if none of the requested files are
// found.
//
// Deprecated: The [Layer.Files] method is deprecated.
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
// Deprecated: Callers should instead use [fs.WalkDir] with the [fs.FS] returned
// by [Layer.FS].
func (l *Layer) Files(paths ...string) (map[string]*bytes.Buffer, error) {
	// Clean the input paths.
	want := make(map[string]struct{})
	for i, p := range paths {
		p := normalizeIn("/", p)
		paths[i] = p
		want[p] = struct{}{}
	}

	f := make(map[string]*bytes.Buffer)
	// Walk the fs. ReadFile will handle symlink resolution.
	if err := fs.WalkDir(l.sys, ".", func(p string, d fs.DirEntry, err error) error {
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
		b, err := fs.ReadFile(l.sys, p)
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

// NoCopy is a marker to get `go vet` to complain about copying.
type noCopy struct{}

func (noCopy) Lock()   {}
func (noCopy) Unlock() {}
