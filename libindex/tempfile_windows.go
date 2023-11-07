package libindex

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	_ "unsafe" // linker tricks
)

// This is a very rough port of src/os/tempfile.go that adds the magic
// autodelete flag.

//go:linkname fastrand runtime.fastrand
func fastrand() uint32

type tempFile struct {
	*os.File
}

func openTemp(dir string) (*tempFile, error) {
	// Copied out of golang.org/x/sys/windows
	const FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	for {
		fn := fmt.Sprintf("fetch.%d", fastrand())
		f, err := os.OpenFile(filepath.Join(dir, fn), os.O_WRONLY|FILE_FLAG_DELETE_ON_CLOSE, 0644)
		switch {
		case errors.Is(err, nil):
			return &tempFile{
				File: f,
			}, nil
		case errors.Is(err, fs.ErrExist):
			// Continue
		default:
			return nil, err
		}
	}
}

func (t *tempFile) Reopen() (*os.File, error) {
	return os.OpenFile(t.Name(), os.O_RDONLY, 0644)
}
