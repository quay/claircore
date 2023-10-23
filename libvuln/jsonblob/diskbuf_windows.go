package jsonblob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	_ "unsafe" // linker tricks
)

// This is a very rough port of src/os/tempfile.go that adds the magic
// autodelete flag.

//go:linkname fastrand runtime.fastrand
func fastrand() uint32

func diskBuf(_ context.Context) (*os.File, error) {
	// Copied out of golang.org/x/sys/windows
	const FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	dir := os.TempDir()
	for {
		fn := fmt.Sprintf("jsonblob.%d.json", fastrand())
		f, err := os.OpenFile(filepath.Join(dir, fn), os.O_RDWR|os.O_CREATE|os.O_EXCL|FILE_FLAG_DELETE_ON_CLOSE, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return f, err
	}
}
