package filterfs

import (
	"io"
	"io/fs"
)

// A ReadDirFile wrapper for fs.File
type DirFile struct {
	fdir    fs.File
	fsys    *FS
	name    string
	entries []fs.DirEntry
	pos     int
}

func (d *DirFile) Close() error               { d.entries = nil; return d.fdir.Close() }
func (d *DirFile) Read(_ []byte) (int, error) { return 0, io.EOF }
func (d *DirFile) Stat() (fs.FileInfo, error) { return d.fdir.Stat() }

func (d *DirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.entries == nil {
		es, err := d.fsys.ReadDir(d.name)
		if err != nil {
			return es, err
		}
		d.entries = es
	}
	es := d.entries[d.pos:]
	if len(es) == 0 {
		if n == -1 {
			return nil, nil
		}
		return nil, io.EOF
	}
	end := min(len(es), n)
	if n == -1 {
		end = len(es)
	}
	d.pos += end
	return es[:end], nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
