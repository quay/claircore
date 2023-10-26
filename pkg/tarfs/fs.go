package tarfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
)

// FS implements [fs.FS] over an optionally compressed tar file.
//
// FS buffers contents as needed.
// [FS.Close] must be called to release any held resources.
type FS struct {
	cleanup io.Closer
	srv
}

// Decompressor is an interface that abstracts over the exact compression scheme used to compress chunks.
type decompressor interface {
	io.Reader
	io.WriterTo
	Reset(io.Reader) error
}

// A bunch of magic constants for zstd.
const (
	zstdFrame             = 0xFD2FB528
	zstdSkippableMask     = 0xFFFFFFF0
	zstdSkippableFrame    = 0x184D2A50
	zstdChunkedFrameMagic = 0x78556E496C556E47
)

// Fixed bytes for the gzip member containing the eStargz's TOC.
var gzipHeader = []byte{0x1f, 0x8b, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}

// New implements a filesystem abstraction over an [io.ReaderAt] containing:
//
//   - An eStargz-compatible tar
//   - A zstd:chunked-compatible tar
//   - An optionally compressed tar
//
// See the links in the package documentation for descriptions of the "eStargz" and "zstd:chunked" schemes.
// Prioritized files specified by eStargz are ignored by this implementation; all file contents are fetched lazily.
// Contents may be compressed via gzip or zstd.
//
// As an optimization, if "r" is an [os.File] containing an uncompressed tar, it will be used directly without internal buffering.
// If the passed "size" is less than zero, the size of the underlying data will attempt to be automatically determined.
// A nil "buf" can be used, but [ErrFileNeeded] will be returned if a backing file is needed.
func New(ctx context.Context, r io.ReaderAt, size int64, buf *os.File) (*FS, error) {
	var (
		// Returned FS
		sys FS
		// Does this constructor need to bail out? Also used for metrics.
		bail = true
		// Some metrics:
		seekable        = false
		compressionKind = `unknown`
	)
	ctx = zlog.ContextWithValues(ctx, "component", `pkg/tarfs.New`)
	ctx, span := tracer.Start(ctx, "New")
	defer func() {
		// This is gigantic, sorry.
		attrs := []attribute.KeyValue{
			attribute.String("compression", compressionKind),
			attribute.Bool("seekable", seekable),
			attribute.Bool("success", !bail),
		}
		span.SetAttributes(attrs...)

		if bail {
			span.SetStatus(codes.Error, "unsuccessful tarfs creation")
			if sys.cleanup != nil {
				if err := sys.cleanup.Close(); err != nil {
					zlog.Warn(ctx).
						AnErr("cleanup", err).
						Msg("errors encountered during error return")
					span.RecordError(err)
				}
			}
		} else {
			span.SetStatus(codes.Ok, "successful tarfs creation")
		}
		fsCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
		span.End()
	}()

	// If passed in a negative number, try to autodetect the size of the reader.
	if size < 0 {
		switch v := r.(type) {
		case interface{ Size() int64 }:
			size = v.Size()
		case interface{ Stat() (fs.FileInfo, error) }:
			fi, err := v.Stat()
			if err != nil {
				return nil, fmt.Errorf("tarfs: unable to stat: %w", err)
			}
			size = fi.Size()
		case io.Seeker:
			var err error
			size, err = v.Seek(0, io.SeekEnd)
			if err != nil {
				return nil, fmt.Errorf("tarfs: unable to seek: %w", err)
			}
			if _, err := v.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("tarfs: unable to seek: %w", err)
			}
		default:
			return nil, errors.New("tarfs: unable to determine size of ReaderAt")
		}
	}

	footer := make([]byte, 64) // Current maximum size for our supported schemes is 51 bytes.
	n, err := r.ReadAt(footer, size-int64(len(footer)))
	switch {
	case errors.Is(err, nil):
	case n == len(footer) && errors.Is(err, io.EOF):
	default:
		return nil, fmt.Errorf("tarfs: unable to read footer: %w", err)
	}

	var toc *toc
	var dec decompressor
	// Examine the footer:
	zframe := footer[len(footer)-48:]
	isZstd := zstdSkippableFrame == (binary.LittleEndian.Uint32(zframe)&zstdSkippableMask) &&
		zstdChunkedFrameMagic == binary.LittleEndian.Uint64(zframe[len(zframe)-8:])
	gframe := footer[len(footer)-51:]
	switch {
	case isZstd:
		z := getZstd()
		dec = z
		compressionKind = `zstd`
		seekable = true
		toc, err = extractZstdTOC(ctx, r, z, zframe)
	case bytes.Equal(gzipHeader, gframe[:len(gzipHeader)]): // isGzip
		z := getGzip()
		dec = z
		compressionKind = `gzip`
		seekable = true
		toc, err = extractGzipTOC(ctx, r, z, gframe)
	default:
		// So this isn't a seekable variant we're aware of.
		//
		// To be extremely cool, try reading a block and see if we can make
		// sense of what's there and handle it as a "normal" tar.
		header := make([]byte, 512)
		switch n, err := r.ReadAt(header, 0); {
		case errors.Is(err, nil): // OK
		case n == len(header) && errors.Is(err, io.EOF): // Single member? Odd, but not _not_ OK.
		default:
			return nil, fmt.Errorf("tarfs: unable to read header: %w", err)
		}
		var unz bool
	Loop:
		switch {
		case bytes.Equal(header[magicOff:][:8], magicOldGNU) ||
			bytes.Equal(header[magicOff:][:6], magicGNU) ||
			bytes.Equal(header[magicOff:][:6], magicPAX):
			if dec == nil {
				compressionKind = `none`
			}
		case !unz && dec != nil:
			// A previous time around this switch populated a decompressor, so
			// load a new block.
			b := make([]byte, 512)
			dec.Reset(io.NewSectionReader(r, 0, -1))
			if _, err = io.ReadFull(dec, b); err != nil {
				// err is set
				break
			}
			header = b
			unz = true
			goto Loop
		case unz:
			err = parseErr("unknown kind")
		case zstdFrame == binary.LittleEndian.Uint32(header):
			dec = getZstd()
			compressionKind = `zstd`
			goto Loop
		case bytes.Equal(gzipHeader[:2], header[:2]): // See RFC1952 2.3.1 for why "2".
			dec = getGzip()
			compressionKind = `gzip`
			goto Loop
		}
		if err != nil {
			return nil, fmt.Errorf("tarfs: error examining standard tar: %w", err)
		}
		// Now that we're here, the following invariants hold:
		//
		// - The uncompressed data from the passed-in ReaderAt *is* a tar, to
		//   our satisfaction.
		// - We need to construct the TOC.
		//
		// Since we need to do a linear read to construct the TOC (as there's no
		// way to tell if the compression frames are amenable to our access
		// pattern), we may as well buffer the whole thing. This is
		// special-cased so that we can read through the stream as it's being
		// decompressed.
		toc, buf, err = buildTOC(ctx, r, dec, buf)
		if err != nil {
			return nil, fmt.Errorf("tarfs: unable to build TOC: %w", err)
		}
		err = sys.init(buf, toc.Entry, inodeIdent)
	}
	if err != nil {
		return nil, fmt.Errorf("tarfs: error initializing FS: %w", err)
	}
	if toc.Version != 1 {
		return nil, errors.New("unsupported version")
	}

	if seekable {
		if buf == nil {
			return nil, ErrFileNeeded
		}
		d, err := newDiskBuf(r, dec, sys.inodeByIdx, buf)
		if err != nil {
			return nil, fmt.Errorf("tarfs: unable to create disk buffer: %w", err)
		}
		sys.cleanup = d
		if err := sys.init(d.buf, toc.Entry, d.fetchFile); err != nil {
			return nil, fmt.Errorf("tarfs: error initializing FS: %w", err)
		}
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&sys, func(sys *FS) {
		panic(fmt.Sprintf("%s:%d: FS not closed", file, line))
	})
	profile.Add(&sys, 1)
	bail = false
	return &sys, nil
}

// Close releases any held resources and reports errors encountered while doing so.
//
// Failing to call Close or calling Close on an instance that was not returned by [New] may result in the program panicing.
func (s *FS) Close() error {
	runtime.SetFinalizer(s, nil)
	profile.Remove(s)
	if s.cleanup != nil {
		return s.cleanup.Close()
	}
	return nil
}

// Interface assertions for FS.
var (
	_ fs.FS         = (*FS)(nil)
	_ fs.GlobFS     = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	// Skipped implementing [fs.SubFS], as sharing the backing buffer
	// would be complicated and probably end up needing a file lock on it.
)

// Assert the two openFunc implementations fulfill the type.
var (
	_ openFunc = (*diskBuf)(nil).fetchFile
	_ openFunc = inodeIdent
)

// InodeIdent is an [openFunc] that uses the values in the passed [inode].
func inodeIdent(r inode) (off, sz int64, err error) {
	return r.Offset, r.Entry.Size, nil
}

// Toc is a table of contents.
type toc struct {
	Entry   []Entry `json:"entries"`
	Version int     `json:"version"`
}
