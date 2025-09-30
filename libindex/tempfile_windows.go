package libindex

import (
	"errors"
	"io/fs"
	"os"
)

// This is a very rough port of src/os/tempfile.go that adds the magic
// autodelete flag.

func openTemp(dir *os.Root) (f *os.File, err error) {
	// Copied out of golang.org/x/sys/windows
	const FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	const flag = os.O_WRONLY | FILE_FLAG_DELETE_ON_CLOSE
	for {
		name := fetchFilename()
		f, err = dir.OpenFile(name, flag, 0o644)
		switch {
		case errors.Is(err, nil):
			return f, nil
		case errors.Is(err, fs.ErrExist):
			// Continue
		default:
			return nil, err
		}
	}
}
