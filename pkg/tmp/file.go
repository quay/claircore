package tmp

import (
	"io/ioutil"
	"os"
)

// File wraps a *os.File and also implements a Close method which cleans up the file
// from the filesystem
type File struct {
	*os.File
}

func NewFile(dir, pattern string) (*File, error) {
	f, err := ioutil.TempFile(dir, pattern)
	if err != nil {
		return nil, err
	}

	return &File{f}, nil
}

// Close closes the file handle and removes the file from the filesystem
func (t *File) Close() error {
	if err := t.File.Close(); err != nil {
		return err
	}
	return os.Remove(t.File.Name())
}
