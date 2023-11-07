package libindex

import "os"

func openTemp(name string, perm os.FileMode) (*os.File, error) {
	// Copied out of golang.org/x/sys/windows
	const FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
	return os.OpenFile(name, os.O_WRONLY|FILE_FLAG_DELETE_ON_CLOSE, perm)
}
