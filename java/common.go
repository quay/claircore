package java

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/quay/zlog"
)

// IsArchive reports whether the file described by the passed tar.Header is some
// form of Java archive.
//
// Assumes slash-separated paths.
func isArchive(ctx context.Context, h *tar.Header) bool {
	base := path.Base(h.Name)
Outer:
	switch {
	case h.Typeflag != tar.TypeReg:
	case strings.HasPrefix(base, ".wh."):
	default:
		switch ext := path.Ext(base); ext {
		case ".jar":
			zlog.Debug(ctx).Str("file", h.Name).Msg("found jar")
		case ".war":
			zlog.Debug(ctx).Str("file", h.Name).Msg("found war")
		case ".ear":
			zlog.Debug(ctx).Str("file", h.Name).Msg("found ear")
		default:
			break Outer
		}
		return true
	}
	return false
}

var (
	// ErrBadHeader is returned by peekHeader when the possible jar is not
	// actually a zip file.
	errBadHeader = errors.New("header indicates this file is not a zip")
	// JAR files are documented as only using the "standard" zip magic number,
	// so that's all I'm checking for here. There are two other magic numbers
	// (ending in "\x05\x06" and "\x07\x08" respectively) for zips, but if I
	// find those in use I'm going to delete this entire package and go flame
	// some people on IRC.
	zipHeader = []byte{'P', 'K', 0x03, 0x04}
)

// PeekHeader looks at the magic prefix of the current file pointed at by the
// tar.Reader and returns either the entirety of the file as an io.Reader or an
// error.
func peekHeader(tr *tar.Reader) (io.Reader, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(tr, b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b, zipHeader) {
		return nil, errBadHeader
	}
	return io.MultiReader(bytes.NewReader(b), tr), nil
}
