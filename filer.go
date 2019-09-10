package claircore

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/quay/claircore/pkg/path"
)

// filer searches a layer for specific files
func filer(l *Layer, paths []string) (map[string][]byte, error) {
	tr, err := tarReader(l)
	if err != nil {
		return nil, err
	}

	// populate our map
	f := map[string][]byte{}
	for _, path := range paths {
		// for convenience lets create file entries for both
		// a leading slashed path a non leading slashed path.
		// the assumption is scanner implementors will commonly make
		// this error. we can be defensive against this bug.
		if strings.HasPrefix(path, "/") {
			noleading := path[1:]
			f[noleading] = []byte{}
			f[path] = []byte{}
		} else {
			// path does not have a leading path, add an entry for one
			leading := fmt.Sprintf("%s%s", "/", path)
			f[leading] = []byte{}
			f[path] = []byte{}
		}
	}

	// iterate over tar headers till io.EOF
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// check if the current header has a path name we are
		// searching for.
		if _, ok := f[hdr.Name]; ok {
			// if file is a link search archive for linked file and return these file blocks
			// as the originally requested file
			var b []byte
			if hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeSymlink {
				// check to see if the file is a relative path. if it is remove any relative pathing
				var ln string
				if !filepath.IsAbs(hdr.Linkname) {
					ln = path.CanonicalizeFileName(hdr.Linkname)
				} else {
					ln = hdr.Linkname
				}

				b, err = retrieveLink(l, ln)
				if err != nil {
					return nil, err
				}
			} else {
				// ... it does so now read all bytes into the pre-allocated buffer until io.EOF
				b = make([]byte, hdr.Size)
				var err1 error
				for err1 == nil {
					_, err1 = tr.Read(b)
				}
				if err1 != io.EOF {
					return nil, err
				}
			}

			// add the buffer for both a leading and non leading path
			// entry. see above comments for why
			f[hdr.Name] = b
			leading := fmt.Sprintf("%s%s", "/", hdr.Name)
			f[leading] = b
		}
	}

	return f, nil
}

// tarReader determines where the contents of a tar exist for the layer and returns a tar.Reader
// initialized to the beggning of the tar contents. if the tar contents cannot be determined an error is returned
// you may call this method multiple times to get a unique tar reader initialized to the start of the archive
func tarReader(l *Layer) (*tar.Reader, error) {
	// if tar is in memory retrieve files from there
	if l.Bytes != nil {
		// we do not want to make a copy of Layer.Bytes so wrap this byte array
		// inside a bytes.Reader and hand this to tar.
		r := bytes.NewReader(l.Bytes)
		tr := tar.NewReader(r)
		return tr, nil
	}

	// if tar is located on disk open file handle and stream the tar contents
	if l.LocalPath != "" {
		fd, err := os.Open(l.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open provided local path: %v", err)
		}
		buffered := bufio.NewReader(fd)

		tr := tar.NewReader(buffered)
		return tr, err
	}

	return nil, fmt.Errorf("layer contents are neither in memory or on disk")
}

// retrieveLink will retrieve the linked file byte array if the file we are searching for is a symbolic or
// hard link. if it cannot be found an empty byte array is returned
func retrieveLink(l *Layer, linkName string) ([]byte, error) {
	tr, err := tarReader(l)
	if err != nil {
		return nil, err
	}

	var b = []byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("error retrieving link: %v", err)
		}

		if hdr.Name == linkName {
			b = make([]byte, hdr.Size)
			var err1 error
			for err1 == nil {
				_, err1 = tr.Read(b)
			}
			if err1 != io.EOF {
				return nil, fmt.Errorf("error retrieving link: %v", err)
			}
		}
	}

	return b, nil
}
