package libindex

import (
	"os"

	"golang.org/x/sys/unix"
)

func openTemp(name string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, os.O_WRONLY|unix.O_TMPFILE, perm)
}
