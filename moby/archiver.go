package moby

import (
	"io"

	mobyarchive "github.com/moby/moby/pkg/archive"
)

// Archiver wraps the moby/pkg/archive package in an interface
type Archiver interface {
	DecompressStream(archive io.Reader) (io.ReadCloser, error)
}

// archive implements our moby.Archive interface
type archiver struct{}

func (a *archiver) DecompressStream(archive io.Reader) (io.ReadCloser, error) {
	rc, err := mobyarchive.DecompressStream(archive)
	return rc, err
}

func NewArchiver() Archiver {
	return &archiver{}
}
