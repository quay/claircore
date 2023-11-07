package libindex

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type tempFile struct {
	*os.File
}

func openTemp(dir string) (*tempFile, error) {
	f, err := os.OpenFile(dir, os.O_WRONLY|unix.O_TMPFILE, 0644)
	if err != nil {
		return nil, err
	}
	return &tempFile{
		File: f,
	}, nil
}

func (t *tempFile) Reopen() (*os.File, error) {
	fd := int(t.Fd())
	if fd == -1 {
		return nil, errStale
	}
	p := fmt.Sprintf("/proc/self/fd/%d", fd)
	// Need to use OpenFile so that the symlink is not dereferenced.
	// There's some proc magic so that opening that symlink itself copies the
	// description.
	return os.OpenFile(p, os.O_RDONLY, 0644)
}
