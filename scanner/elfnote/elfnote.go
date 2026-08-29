// Package elfnote extracts package information from metadata stored in an ELF
// binary.
//
// See https://lwn.net/Articles/874642/,
// https://fedoraproject.org/wiki/Changes/Package_information_on_ELF_objects,
// and https://systemd.io/COREDUMP_PACKAGE_METADATA/ for details.
package elfnote

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

type Scanner struct{}

const (
	pkgName    = `elfnote`
	pkgVersion = `1`
	pkgKind    = `package`

	packageNote = `.note.package`

	toobig = 4 << 20 // 4 MiB
)

// Name implements [indexer.VersionedScanner].
func (*Scanner) Name() string { return pkgName }

// Version implements [indexer.VersionedScanner].
func (*Scanner) Version() string { return pkgVersion }

// Kind implements [indexer.VersionedScanner].
func (*Scanner) Kind() string { return pkgKind }

// Scan attempts to find and enumerate ELF files.
func (s *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	sys, err := layer.FS()
	if err != nil {
		return nil, fmt.Errorf(`elfnote: unable to open layer: %w`, err)
	}

	w := newWalker(sys)
	if err := fs.WalkDir(sys, ".", w.Walk(ctx)); err != nil {
		return nil, err
	}

	if ct := len(w.out); ct != 0 {
		zlog.Info(ctx).
			Int("count", ct).
			Msg("found annotated binaries")
	} else {
		return nil, nil
	}
	return w.out, nil
}

type walker struct {
	buf bytes.Buffer
	sys fs.FS
	hb  []byte
	out []*claircore.Package
}

func newWalker(sys fs.FS) *walker {
	w := &walker{
		sys: sys,
		hb:  make([]byte, 4),
		out: make([]*claircore.Package, 0, 512), // guess at initial cap
	}
	w.buf.Grow(toobig)
	return w
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

		note, err := readNote(ctx, bytes.NewReader(w.buf.Bytes()))
		switch {
		case err == nil:
			w.out = append(w.out, note.Package())
		case errors.Is(err, errNoNote):
			// Nothing to do.
		default:
			return fmt.Errorf(`elfnote: error opening ELF: %w`, err)
		}
		return nil
	}
}

var (
	errNoNote = errors.New("no note")
	errSkip   = errors.New("skip note")
)

func readNote(ctx context.Context, r io.ReaderAt) (*note, error) {
	exe, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf(`elfnote: error opening ELF: %w`, err)
	}
	defer exe.Close()
	s := exe.Section(packageNote)
	if s == nil {
		return nil, nil // errNoNote
	}

	bin := exe.ByteOrder
	notes := bufio.NewReader(s.Open())
	for {
		n, err := unmarshalNote(ctx, bin, notes)
		switch {
		case err == nil:
			return n, nil
		case errors.Is(err, errSkip):
			continue
		default:
			return nil, err
		}
	}
}

// Align returns "n" as a 4-aligned count.
func align(n uint32) int {
	return int((n - 1 | 3) + 1)
}

func unmarshalNote(_ context.Context, bin binary.ByteOrder, r *bufio.Reader) (*note, error) {
	// The values we read are at least NUL terminated. They should be
	// NUL-padded, but just clip at the first NUL.
	cstr := func(b []byte) []byte {
		i := bytes.IndexByte(b, 0x00)
		return b[:i]
	}

	// Header fields
	const (
		nameSz = iota
		valueSz
		typ
	)
	var hdr [3]uint32

	for i := range 3 {
		b, err := r.Peek(4)
		switch {
		case err == nil:
		case errors.Is(err, io.EOF) && len(b) == 0:
			return nil, nil
		default:
			return nil, err // TODO
		}
		hdr[i] = bin.Uint32(b)
		r.Discard(4)
	}
	if hdr[typ] != 0xcafe1a7e /* type id */ {
		return nil, errSkip
	}

	valueOff := align(hdr[nameSz])
	totalSz := valueOff + align(hdr[valueSz])
	defer r.Discard(totalSz)
	b, err := r.Peek(totalSz)
	if err != nil {
		return nil, err // TODO
	}

	if !bytes.Equal(cstr(b), []byte(`FDO`)) {
		return nil, errSkip
	}

	var n note
	if err := json.Unmarshal(cstr(b[valueOff:]), &n); err != nil {
		return nil, fmt.Errorf(`elfnote: unmarshal error: %w`, err)
	}
	return &n, nil
}

type note struct {
	Type         string  `json:"type"`
	OS           string  `json:"os"`
	OSVersion    string  `json:"osVersion"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Arch         string  `json:"architecture"`
	OSCPE        cpe.WFN `json:"osCpe"`
	CPE          cpe.WFN `json:"appCpe"`
	DebugInfoURL string  `json:"debugInfoUrl"`
}

func (n *note) Package() *claircore.Package {
	panic(errors.ErrUnsupported)
}
