//go:build !linux

package libindex

import "os"

func reopen(f *os.File) (*os.File, error) {
	return os.OpenFile(f.Name(), os.O_RDONLY, 0o644)
}
