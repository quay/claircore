//go:build !linux

package libindex

import "os"

func reopen(dir *os.Root, f *os.File) (*os.File, error) {
	return dir.OpenFile(f.Name(), os.O_RDONLY, 0o644)
}
