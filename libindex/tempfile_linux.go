package libindex

import (
	"errors"
	"io/fs"
	"os"
	"sync"
	"weak"

	"golang.org/x/sys/unix"
)

var tmpMap = struct {
	sync.RWMutex
	// This map never gets cleaned up, but also never pins the [os.Root] object.
	dir map[weak.Pointer[os.Root]]bool
}{
	dir: make(map[weak.Pointer[os.Root]]bool),
}

func canTmp(dir *os.Root) bool {
	key := weak.Make(dir)
	tmpMap.RLock()
	ok, loaded := tmpMap.dir[key]
	tmpMap.RUnlock()
	// want the default inverted:
	if !loaded {
		ok = tryTMPFILE
	}
	return ok
}

func setTmp(dir *os.Root, ok bool) {
	key := weak.Make(dir)
	tmpMap.Lock()
	defer tmpMap.Unlock()
	tmpMap.dir[key] = ok
}

func openTemp(dir *os.Root) (f *os.File, err error) {
	tmpOK := canTmp(dir)

Loop:
	for {
		name := "."
		flag := os.O_WRONLY
		if !tmpOK {
			name = fetchFilename()
			flag |= os.O_CREATE | os.O_EXCL // Create new file, fail if exists
		} else {
			flag |= unix.O_TMPFILE
		}
		f, err = dir.OpenFile(name, flag, 0o644)
		switch {
		case tmpOK && errors.Is(err, unix.ENOTSUP):
			tmpOK = false
			setTmp(dir, false)
			// Now try again using the fallback path.
		case !tmpOK && errors.Is(err, fs.ErrExist):
			// Try again because the process just guessed a bad name.
		default:
			break Loop
		}
	}
	if !tmpOK && err == nil {
		// This is just a best-effort action to keep files from accumulating.
		// The correct way is to use the kernel feature for this: the O_TMPFILE flag.
		_ = dir.Remove(f.Name())
	}

	if err != nil {
		return nil, err
	}
	return f, nil
}
