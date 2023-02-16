// Package gobin implements a package scanner that pulls go runtime and
// dependency information out of a compiled executable.
package gobin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime/trace"
	"sync"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
)

// Detector detects go binaries and reports the packages used to build them.
type Detector struct{}

const (
	detectorName    = `gobin`
	detectorVersion = `2`
	detectorKind    = `package`
)

var _ indexer.PackageScanner = Detector{}

// Name implements [indexer.PackageScanner].
func (Detector) Name() string { return detectorName }

// Version implements [indexer.PackageScanner].
func (Detector) Version() string { return detectorVersion }

// Kind implements [indexer.PackageScanner].
func (Detector) Kind() string { return detectorKind }

// Scan implements [indexer.PackageScanner].
func (Detector) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Package, error) {
	const peekSz = 4
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", l.Hash.String())
	ctx = zlog.ContextWithValues(ctx,
		"component", "gobin/Detector.Scan",
		"version", detectorVersion,
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	rd, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, err
	}

	var out []*claircore.Package

	peek := make([]byte, peekSz)
	// Spooling support.
	//
	// Only create a single spool file per call, re-use for every binary.
	var spool spoolfile
	walk := func(p string, d fs.DirEntry, err error) error {
		ctx := zlog.ContextWithValues(ctx, "path", d.Name())
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case ctx.Err() != nil:
			return ctx.Err()
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m := fi.Mode()
		switch {
		case !m.IsRegular():
			return nil
		case m.Perm()&0o555 == 0:
			// Not executable
			return nil
		}
		f, err := sys.Open(p)
		if err != nil {
			// TODO(crozzy): Remove log line once controller is in a
			// position to log all the context when receiving an error.
			zlog.Warn(ctx).Msg("unable to open file")
			return fmt.Errorf("gobin: unable to open %q: %w", p, err)
		}
		defer f.Close()

		_, err = io.ReadFull(f, peek)
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			// Valid error with empty, or tiny files.
			return nil
		default:
			// TODO(crozzy): Remove log line once controller is in a
			// position to log all the context when receiving an error.
			zlog.Warn(ctx).Msg("unable to read file")
			return fmt.Errorf("gobin: unable to read %q: %w", p, err)
		}

		if !bytes.HasPrefix(peek, []byte("\x7fELF")) && !bytes.HasPrefix(peek, []byte("MZ")) {
			// not an ELF or PE binary
			return nil
		}
		rd, ok := f.(io.ReaderAt)
		if !ok {
			// Need to spool the exe.
			if err := spool.Setup(); err != nil {
				return fmt.Errorf("gobin: unable to setup spool: %w", err)
			}
			if _, err := spool.File.Write(peek); err != nil {
				return fmt.Errorf("gobin: unable to spool %q: %w", p, err)
			}
			sz, err := io.Copy(spool.File, f)
			if err != nil {
				return fmt.Errorf("gobin: unable to spool %q: %w", p, err)
			}
			rd = io.NewSectionReader(spool.File, 0, sz+peekSz)
		}
		return toPackages(ctx, &out, p, rd)
	}
	if err := fs.WalkDir(sys, ".", walk); err != nil {
		return nil, err
	}

	return out, nil
}

type spoolfile struct {
	sync.Once
	File *os.File
	err  error
}

func (s *spoolfile) Setup() error {
	s.Do(s.setup)
	if s.err != nil {
		return s.err
	}
	if _, err := s.File.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return nil
}

func (s *spoolfile) setup() {
	f, err := os.CreateTemp("", "gobin.spool.*")
	if err != nil {
		s.err = err
		return
	}
	if err := os.Remove(f.Name()); err != nil {
		s.err = err
		return
	}
	s.File = f
}
