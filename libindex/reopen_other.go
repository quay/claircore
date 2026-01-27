//go:build !linux

package libindex

import (
	"os"
	"path/filepath"
)

func reopen(dir *os.Root, f *os.File) (*os.File, error) {
	return dir.OpenFile(filepath.Base(f.Name()), os.O_RDONLY, 0o644)
}
