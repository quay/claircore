package jsonblob

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

func diskBuf(_ context.Context) (*os.File, error) {
	return os.OpenFile(os.TempDir(), os.O_RDWR|unix.O_TMPFILE, 0600)
}
