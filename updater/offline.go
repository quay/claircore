package updater

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"

	"github.com/klauspost/compress/zstd"
)

// Fetch runs only the Fetch step of the update process, writing it out to
// "out".
//
// If "prev" is populated with the output of a previous run of this method, only
// changes since what was recorded in "prev" are written out.
func (u *Updater) Fetch(ctx context.Context, prev io.ReaderAt, out io.Writer) error {
	z := zip.NewWriter(out)
	var prevFS fs.FS
	if prev != nil {
		pz, h, err := openZip(prev)
		if err != nil {
			return err
		}
		if h == exportV1 {
			prevFS = pz
		}
	}
	if err := u.exportV1(ctx, z, prevFS); err != nil {
		return err
	}
	v := make(url.Values)
	v.Set(exportHeader, exportV1)
	if err := z.SetComment(v.Encode()); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	if f, ok := out.(syncer); ok {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

type syncer interface{ Sync() error }

// Parse runs the "second half" of the update process, using the contents of
// "in," which must have been populated by a previous call to Fetch.
//
// The reader at "in" must have some way to detect its size.
func (u *Updater) Parse(ctx context.Context, in io.ReaderAt) error {
	z, h, err := openZip(in)
	if err != nil {
		return err
	}
	switch h {
	case exportV1:
		return u.importV1(ctx, z)
	case "":
		return errors.New("updater: file not produced by claircore")
	default:
	}
	return fmt.Errorf("updater: unrecognized export version %q", h)
}

// OpenZip opens the zip pointed to by f if a size can be determined, and also
// returns the magic comment, if present.
func openZip(in io.ReaderAt) (*zip.Reader, string, error) {
	var sz int64
	switch v := in.(type) {
	case sizer:
		sz = v.Size()
	case fileStat:
		fi, err := v.Stat()
		if err != nil {
			return nil, "", err
		}
		sz = fi.Size()
	case io.Seeker:
		cur, err := v.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, "", err
		}
		sz, err = v.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, "", err
		}
		if _, err := v.Seek(cur, io.SeekStart); err != nil {
			return nil, "", err
		}
	default:
		return nil, "", errors.New("updater: unable to determine size of zip file")
	}
	z, err := zip.NewReader(in, sz)
	if err != nil {
		return nil, "", err
	}
	v, _ := url.ParseQuery(z.Comment)
	return z, v.Get(exportHeader), nil
}

type (
	fileStat interface{ Stat() (fs.FileInfo, error) }
	sizer    interface{ Size() int64 }
)

const (
	exportHeader    = `ClaircoreUpdaterExport`
	zstdCompression = 93 // zstd, according to PKWARE spec
)

func init() {
	zip.RegisterCompressor(zstdCompression, newZstdCompressor)
	zip.RegisterDecompressor(zstdCompression, newZstdDecompressor)
}

func newZstdCompressor(w io.Writer) (io.WriteCloser, error) {
	c, err := zstd.NewWriter(w)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func newZstdDecompressor(r io.Reader) io.ReadCloser {
	c, err := zstd.NewReader(r)
	if err != nil {
		panic(err)
	}
	return &cmpWrapper{c}
}

type cmpWrapper struct {
	*zstd.Decoder
}

func (w *cmpWrapper) Close() error {
	w.Decoder.Close()
	return nil
}
