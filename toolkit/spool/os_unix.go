//go:build unix && !linux

package spool

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
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

func osAdjustName(name string) string { return name }

func osAdjustFlag(flag int) int {
	return flag & os.O_CREATE
}

func osAddCleanup(f *os.File) {
	runtime.AddCleanup(f, func(name string) { root.Remove(name) }, f.Name())
}

// Reopen provides or emulates re-opening a file and obtaining an independent file description.
func Reopen(f *os.File, flag int) (*os.File, error) {
	if flag&os.O_CREATE != 0 {
		return nil, fmt.Errorf("spool: cannot pass O_CREATE to Reopen: %w", fs.ErrInvalid)
	}
	return root.OpenFile(f.Name(), flag, 0)
}
