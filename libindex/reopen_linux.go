package libindex

import (
	"errors"
	"fmt"
	"os"
)

func reopen(_ *os.Root, f *os.File) (*os.File, error) {
	fd := int(f.Fd())
	if fd == -1 {
		return nil, errors.New("stale file descriptor")
	}
	p := fmt.Sprintf("/proc/self/fd/%d", fd)
	// Need to use OpenFile so that the symlink is not dereferenced.
	// There's some proc magic so that opening that symlink itself copies the
	// description.
	return os.OpenFile(p, os.O_RDONLY, 0o644)
}
