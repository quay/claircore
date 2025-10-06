package spool

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

// Init initializes [root].
func init() {
	var p string

	// If the environment was explicitly set, use it.
	var ok bool
	if p, ok = os.LookupEnv("TMPDIR"); ok {
		goto Open
	}

	// Try to honor file-hierarchy(7).
	for _, name := range []string{`/var/tmp`, os.TempDir()} {
		fi, err := os.Stat(name)
		if err == nil && fi.IsDir() {
			p = name
			goto Open
		}
	}

Open:
	var err error
	root, err = os.OpenRoot(p)
	if err != nil {
		panic(err)
	}
}

func checkRootTmpFile() bool {
	f, err := root.OpenFile(".", os.O_WRONLY|unix.O_TMPFILE, 0o600)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

var haveTmpFile = sync.OnceValue(checkRootTmpFile)

func osAdjustName(name string) string {
	if haveTmpFile() {
		return "."
	}
	return name
}

func osAdjustFlag(flag int) int {
	if haveTmpFile() && (flag&os.O_CREATE != 0) {
		// If we can use tmp, do so.
		flag &= ^os.O_CREATE
		flag |= unix.O_TMPFILE
	}
	return flag
}

func osAddCleanup(f *os.File) {
	// If not opened with O_TMPFILE (or there was an error), arrange for the
	// file to be removed.
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_TMPFILE == 0 {
		runtime.AddCleanup(f, func(name string) { root.Remove(name) }, f.Name())
	}
}

// Reopen provides or emulates re-opening a file and obtaining an independent file description.
//
// The Linux implementation reopens files via [magic symlinks] in [proc].
//
// [magic symlinks]: https://www.man7.org/linux/man-pages/man7/symlink.7.html
// [proc]: https://man7.org/linux/man-pages/man5/proc.5.html
func Reopen(f *os.File, flag int) (*os.File, error) {
	if flag&os.O_CREATE != 0 {
		return nil, fmt.Errorf("spool: cannot pass O_CREATE to Reopen: %w", fs.ErrInvalid)
	}
	fd := int(f.Fd())
	if fd == -1 {
		return nil, fs.ErrClosed
	}
	p := fmt.Sprintf("/proc/self/fd/%d", fd)

	return os.OpenFile(p, flag, 0)
}
