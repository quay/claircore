package claircore

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// RemotePath provides http retrieval information about a layer.
type RemotePath struct {
	URI     string              `json:"uri"`
	Headers map[string][]string `json:"headers"`
}

// Layer is an containers image filesystem layer. Layers are stacked
// ontop of each other to comprise the final filesystem of the container image.
type Layer struct {
	// content addressable hash unequally identifying this layer. libscan will treat layers with this same
	// hash as identical.
	Hash string `json:"hash"`
	// format of the archived layer. currently we support tar with Gzip, Bzip2, and Xz compression. compression
	// format will be determined via moby library.
	Format string `json:"format"`
	// the format of this image. typically this is the container technology which created the image.
	ImageFormat string `json:"image_format"`
	// uncompressed tar archive of the layer's content read into memory
	Bytes []byte `json:"-"`
	// path to local file containing uncompressed tar archive of the layer's content
	LocalPath string `json:"-"`
	// the URI and header information for retrieving a layer via http
	RemotePath RemotePath `json:"remote_path"`
}

// Reader returns a ReadCloser of the layer.
//
// It should also implement io.Seeker, and should be a tar stream.
func (l *Layer) Reader() (io.ReadCloser, error) {
	if l.Bytes != nil {
		return ioutil.NopCloser(bytes.NewReader(l.Bytes)), nil
	}
	if l.LocalPath == "" {
		return nil, fmt.Errorf("claircore: malformed Layer struct")
	}
	f, err := os.Open(l.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("claircore: unable to open tar: %w", err)
	}
	return f, nil
}

// Files retrieves specific files from the tar archive. concurrency safe
// as we only read. if file is not found an empty byte array will be returned
// as value in the map key'd by the path name.
func (l *Layer) Files(paths []string) (map[string][]byte, error) {
	m, err := filer(l, paths)
	return m, err
}
