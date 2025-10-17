package libindex

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	tmpMap sync.Map

	errStale = errors.New("stale file reference")
)

func canTmp(dir string) (ok, loaded bool) {
	v, loaded := tmpMap.Load(dir)
	if v == nil {
		return false, loaded
	}
	return v.(bool), loaded
}

func setTmp(dir string, ok bool) {
	tmpMap.Store(dir, ok)
}

type tempFile struct {
	*os.File
}

func openTemp(dir string) (*tempFile, error) {
	var f *os.File
	var err error

	ok, loaded := canTmp(dir)
	switch {
	case loaded && ok:
		f, err = os.OpenFile(dir, os.O_WRONLY|unix.O_TMPFILE, 0644)
	case loaded && !ok:
		f, err = os.CreateTemp(dir, "fetcher.*")
	case !loaded:
		f, err = os.OpenFile(dir, os.O_WRONLY|unix.O_TMPFILE, 0644)
		if err == nil || !errors.Is(err, unix.ENOTSUP) {
			ok = true
			break
		}
		f, err = os.CreateTemp(dir, "fetcher.*")
	default:
		panic("unreachable")
	}
	if !loaded {
		setTmp(dir, ok)
	}
	if !ok && err == nil {
		// This is just a best-effort action to keep files from accumulating.
		// The correct way is to use the kernel feature for this: the O_TMPFILE flag.
		_ = os.Remove(f.Name())
	}

	if err != nil {
		return nil, err
	}
	return &tempFile{File: f}, nil
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
