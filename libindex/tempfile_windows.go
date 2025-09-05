package libindex

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
)

// This is a very rough port of src/os/tempfile.go that adds the magic
// autodelete flag.

type tempFile struct {
	*os.File
}

func openTemp(dir string) (*tempFile, error) {
	// Copied out of golang.org/x/sys/windows
	const FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	for {
		fn := fmt.Sprintf("fetch.%08x", rand.Uint32())
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
