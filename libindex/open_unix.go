//go:build unix && !linux

package libindex

import "os"

func openTemp(name string, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(name, os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
