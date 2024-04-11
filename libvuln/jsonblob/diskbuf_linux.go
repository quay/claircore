package jsonblob

import (
	"context"
	"errors"
	"os"
)

// BUG(hank) On Linux, the disk buffering unconditionally uses what [os.TempDir]
// reports. On most systems, this will be a tmpfs, which means the contents are
// stored in RAM anyway. To mitigate this, set the "TMPDIR" environment variable
// for any process that's using this package.

// TODO(hank) Consolidate the spool/tempfile logic, or at least the directory
// selection logic.

func diskBuf(_ context.Context) (*os.File, error) {
	f, err := os.CreateTemp("", "jsonblob.")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}
