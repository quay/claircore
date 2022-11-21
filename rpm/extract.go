package rpm

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/quay/zlog"
)

func extractTar(ctx context.Context, rd io.ReadSeeker) (string, error) {
	root, err := ioutil.TempDir("", "rpmscanner.")
	if err != nil {
		return "", err
	}
	empty := filepath.Join(os.TempDir(), "rpm.emptyfile")
	ef, err := os.Create(empty)
	if err != nil {
		return "", err
	}
	if err := ef.Close(); err != nil {
		return "", err
	}

	// Extract tarball
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := rd.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rpm: unable to seek: %w", err)
	}
	tr := tar.NewReader(rd)
	const (
		// Any mode bits need to be or'd with these constants so that this
		// process can always remove and traverse files it writes.
		dirMode  = 0o0700
		fileMode = 0o0600
	)
	// For logging what we've done.
	var stats struct {
		Reg, Link, Symlink, Dir, Whiteout int
		OutOfOrder                        int
	}
	// Made tracks directory creation to prevent excessive mkdir calls.
	made := map[string]struct{}{root: {}}
	// DeferLn is for queuing up out-of-order hard links.
	var deferLn [][2]string
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		if strings.HasPrefix(filepath.Base(h.Name), ".wh.") {
			// Whiteout, skip.
			stats.Whiteout++
			continue
		}
		// Build the path on the filesystem.
		tgt := relPath(root, h.Name)
		// Since tar, as a format, doesn't impose ordering requirements, make
		// sure to create all parent directories of the current entry.
		d := filepath.Dir(tgt)
		if _, ok := made[d]; !ok {
			if err := os.MkdirAll(d, dirMode); err != nil {
				return "", err
			}
			made[d] = struct{}{}
			stats.OutOfOrder++
		}

		// Populate the target file.
		var err error
		switch h.Typeflag {
		case tar.TypeDir:
			m := h.FileInfo().Mode() | dirMode
			if _, ok := made[tgt]; ok {
				// If we had made this directory by seeing a child first, touch
				// up the permissions.
				err = os.Chmod(tgt, m)
				break
			}
			err = os.Mkdir(tgt, m)
			if errors.Is(err, os.ErrExist) {
				err = nil
			}
			// Make sure to preempt the MkdirAll call if the entries were
			// ordered nicely.
			made[d] = struct{}{}
			stats.Dir++
		case tar.TypeReg:
			m := h.FileInfo().Mode() | fileMode
			var f *os.File
			f, err = os.OpenFile(tgt, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, m)
			if err != nil {
				break // Handle after the switch.
			}
			_, err = io.Copy(f, tr)
			if err := f.Close(); err != nil {
				zlog.Warn(ctx).
					Err(err).
					Str("path", tgt).
					Msg("error closing new file")
			}
			stats.Reg++
		case tar.TypeSymlink:
			// Normalize the link target into the root.
			ln := relPath(root, h.Linkname)
			err = os.Symlink(ln, tgt)
			stats.Symlink++
		case tar.TypeLink:
			// Normalize the link target into the root.
			ln := relPath(root, h.Linkname)
			_, exists := os.Lstat(ln)
			switch {
			case errors.Is(exists, nil):
				err = os.Link(ln, tgt)
			case errors.Is(exists, os.ErrNotExist):
				// Push onto a queue to fix later. Link(2) is documented to need
				// a valid target, unlike symlink(2), which allows a missing
				// target. Combined with tar's lack of ordering, this seems like
				// the best solution.
				deferLn = append(deferLn, [2]string{ln, tgt})
			default:
				err = exists
			}
			stats.Link++
		default:
			// Skip everything else: Can't mknod as an unprivileged user and
			// fifos are only useful to a running system.
		}
		if err != nil {
			return "", err
		}
	}
	if err != io.EOF {
		return "", err
	}
	for _, l := range deferLn {
		if err := os.Link(l[0], l[1]); err != nil {
			zlog.Debug(ctx).
				Err(err).
				Msg("cross-layer (or invalid) hardlink found")
			if err := os.Link(empty, l[1]); err != nil {
				return "", err
			}
		}
	}
	if ct := len(deferLn); ct != 0 {
		zlog.Debug(ctx).
			Int("count", ct).
			Msg("processed deferred links")
	}

	zlog.Info(ctx).
		Int("file", stats.Reg).
		Int("dir", stats.Dir).
		Int("dir(out of order)", stats.OutOfOrder).
		Int("symlink", stats.Symlink).
		Int("link", stats.Link).
		Int("whiteout", stats.Whiteout).
		Msg("extracted layer")
	return root, nil
}
