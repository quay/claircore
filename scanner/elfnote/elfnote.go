// Package elfnote extracts package information from metadata stored in an ELF
// binary.
//
// See https://lwn.net/Articles/874642/,
// https://fedoraproject.org/wiki/Changes/Package_information_on_ELF_objects,
// and https://systemd.io/COREDUMP_PACKAGE_METADATA/ for details.
package elfnote

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
)

type Scanner struct{}

const (
	pkgName    = `elfnote`
	pkgVersion = `1`
	pkgKind    = `package`

	packageNote = `.note.package`

	toobig = 30 * (1024 * 1024) // 30MiB
)

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return pkgName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return pkgVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return pkgKind }

// Scan attempts to find and enumerate ELF files.
func (s *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	rc, err := layer.Reader()
	if err != nil {
		return nil, fmt.Errorf(`elfnote: unable to open layer: %w`, err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			zlog.Info(ctx).
				Err(err).
				Msg("error closing reader")
		}
	}()
	sys, err := tarfs.New(rc)
	if err != nil {
		return nil, fmt.Errorf(`elfnote: unable to open layer: %w`, err)
	}

	w := walker{
		sys: sys,
		hb:  make([]byte, 4),
		out: make([]*claircore.Package, 0, 512), // guess at initial cap
	}
	w.buf.Grow(toobig)
	if err := fs.WalkDir(sys, ".", w.Walk(ctx)); err != nil {
		return nil, err
	}

	if ct := len(w.out); ct != 0 {
		zlog.Info(ctx).
			Int("count", ct).
			Msg("found annotated binaries")
	}
	return w.out, nil
}

type walker struct {
	buf bytes.Buffer
	sys fs.FS
	hb  []byte
	out []*claircore.Package
}

func (w *walker) Walk(ctx context.Context) fs.WalkDirFunc {
	return func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return fmt.Errorf(`elfnote: error stat'ing %q: %w`, p, err)
		}
		if fi.Mode().Perm()&0o111 == 0 { // if not executable
			return nil
		}
		ctx := zlog.ContextWithValues(ctx, "file", p)

		w.buf.Reset()
		f, err := w.sys.Open(p)
		if err != nil {
			return fmt.Errorf(`elfnote: error opening %q: %w`, p, err)
		}
		defer f.Close()

		if _, err := io.ReadFull(f, w.hb); err != nil {
			return fmt.Errorf(`elfnote: error reading header of %q: %w`, p, err)
		}
		if string(w.hb) != elf.ELFMAG {
			// not an ELF file, skip
			return nil
		}

		w.buf.Reset()
		if _, err := w.buf.Write(w.hb); err != nil {
			return fmt.Errorf(`elfnote: write error: %w`, err)
		}
		if _, err := w.buf.ReadFrom(io.LimitReader(f, toobig)); err != nil {
			return fmt.Errorf(`elfnote: write error: %w`, err)
		}
		if sz := fi.Size(); sz > toobig {
			zlog.Debug(ctx).
				Int64("size", sz).
				Msg("file truncated")
		}

		exe, err := elf.NewFile(bytes.NewReader(w.buf.Bytes()))
		if err != nil {
			return fmt.Errorf(`elfnote: error opening ELF: %w`, err)
		}
		defer exe.Close()
		s := exe.Section(packageNote)
		if s == nil {
			return nil
		}
		b, err := s.Data()
		if err != nil {
			return fmt.Errorf(`elfnote: error reading section %q: %w`, packageNote, err)
		}
		var n note
		if err := json.Unmarshal(b, &n); err != nil {
			return fmt.Errorf(`elfnote: unmarshal error: %w`, err)
		}
		w.out = append(w.out, n.Package())
		return nil
	}
}

type note struct {
	Type      string `json:"type"`
	OS        string `json:"os"`
	OSVersion string `json:"osVersion"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Arch      string `json:"architecture"`
	OSCPE     string `json:"osCpe"`
}

func (n *note) Package() *claircore.Package {
	return nil
}
