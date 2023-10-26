package tarfs

import (
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

// Entry is an entry describing a file or a file chunk.
//
// This is the concrete type backing [fs.FileInfo] interfaces returned by
// this package.
type Entry struct {
	Xattrs      map[string]string `json:"xattrs"`
	Type        string            `json:"type"`
	Name        string            `json:"name"` // NB This is actually the path.
	Linkname    string            `json:"linkName"`
	Digest      string            `json:"digest"`
	ChunkDigest string            `json:"chunkDigest"`
	UserName    string            `json:"userName"`  // eStargz only
	GroupName   string            `json:"groupName"` // eStargz only
	ModTime     time.Time         `json:"modtime"`
	AccessTime  time.Time         `json:"accesstime"` // Zstd chunked only
	ChangeTime  time.Time         `json:"changetime"` // Zstd chunked only
	Mode        int64             `json:"mode"`
	Size        int64             `json:"size"`
	Devmajor    int64             `json:"devMajor"`
	Devminor    int64             `json:"devMinor"`
	Offset      int64             `json:"offset"`
	EndOffset   int64             `json:"endOffset"` // Zstd chunked only
	ChunkSize   int64             `json:"chunkSize"`
	ChunkOffset int64             `json:"chunkOffset"`
	UID         int               `json:"uid"`
	GID         int               `json:"gid"`
}

// Entry types.
const (
	typeDir      = `dir`
	typeReg      = `reg`
	typeSymlink  = `symlink`
	typeHardlink = `hardlink`
	typeChar     = `char`
	typeBlock    = `block`
	typeFifo     = `fifo`
	typeChunk    = `chunk`
)

// NewEntryDir returns a new Entry describing a directory at the path "n".
func newEntryDir(n string) Entry {
	return Entry{
		Name: n,
		Mode: int64(fs.ModeDir | 0o644),
		Type: typeDir,
	}
}

// SortDirent returns a function suitable to pass to [sort.Slice] as a "cmp"
// function.
//
// This is needed because the [io/fs] interfaces specify that [fs.DirEntry]
// slices returned by the ReadDir methods are sorted lexically.
func sortDirent(s []fs.DirEntry) func(i, j int) bool {
	return func(i, j int) bool {
		return strings.Compare(s[i].Name(), s[j].Name()) == -1
	}
}

// Dirent implements [fs.DirEntry] using a backing [*Entry].
type dirent struct{ *Entry }

// Interface assertion for dirent.
var _ fs.DirEntry = dirent{}

// Name implements [fs.DirEntry].
func (d dirent) Name() string { return path.Base(d.Entry.Name) }

// IsDir implements [fs.DirEntry].
func (d dirent) IsDir() bool { return d.Entry.Type == typeDir }

// Type implements [fs.DirEntry].
func (d dirent) Type() fs.FileMode { return fs.FileMode(d.Entry.Mode) & fs.ModeType }

// Info implements [fs.DirEntry].
func (d dirent) Info() (fs.FileInfo, error) {
	return &inode{Entry: d.Entry}, nil
}

// File implements [fs.File] and [fs.ReadDirFile].
//
// The ReadDir method errors if called on a non-dir file.
// The Read methods are implemented by a shared 0-size SectionReader for dir files.
type file struct {
	inode
	*io.SectionReader
	dirent []fs.DirEntry
	dirpos int
}

// Interface assertions for file.
var (
	_ fs.ReadDirFile = (*file)(nil)
	_ fs.File        = (*file)(nil)

	// Extra interfaces that we don't *need* to implement, but do for certain
	// important use cases (namely reading sqlite databases).
	_ io.Seeker   = (*file)(nil)
	_ io.ReaderAt = (*file)(nil)
)

// Close implements [fs.File].
func (f *file) Close() error { return nil }

// Stat implements [fs.File].
func (f *file) Stat() (fs.FileInfo, error) { return &f.inode, nil }

// ReadDir implements [fs.ReadDirFile].
func (f *file) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.Type != `dir` {
		return nil, &fs.PathError{
			Op:   `readdir`,
			Path: f.Entry.Name,
			Err:  fs.ErrInvalid,
		}
	}
	es := f.dirent[f.dirpos:]
	end := min(len(es), n)
	switch {
	case len(es) == 0 && n <= 0:
		return nil, nil
	case len(es) == 0 && n > 0:
		return nil, io.EOF
	case n <= 0:
		end = len(es)
	default:
	}
	f.dirpos += end
	return es[:end], nil
}
