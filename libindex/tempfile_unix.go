//go:build unix && !linux

package libindex

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
)

func openTemp(dir *os.Root) (f *os.File, err error) {
	const flag = os.O_WRONLY
	for {
		name := fetchFilename()
		f, err = dir.OpenFile(name, flag, 0o644)
		// NB This breaks out of the loop on any condition *except* an "exists"
		// error.
		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	runtime.AddCleanup(f, func(n string) { dir.Remove(n) }, f.Name())
	return f, nil
}
