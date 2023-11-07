//go:build unix && !linux

package libindex

import (
	"errors"
	"os"
)

type tempFile struct {
	*os.File
}

func openTemp(dir string) (*tempFile, error) {
	f, err := os.CreateTemp(dir, "*.fetch")
	if err != nil {
		return nil, err
	}
	return &tempFile{
		File: f,
	}, nil
}

func (t *tempFile) Reopen() (*os.File, error) {
	return os.OpenFile(t.Name(), os.O_RDONLY, 0644)
}

func (t *tempFile) Close() error {
	return errors.Join(os.Remove(t.Name()), t.File.Close())
}
