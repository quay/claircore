package tarfs

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"go.opentelemetry.io/otel/attribute"
)

// ErrFormat can be compared via [errors.Is] against errors reported by
// [New] to determine if the tar file or relevant footer is considered
// well-formed.
var ErrFormat = errors.New("tarfs: format error reading file")

// ParseErr returns an error that [errors.Is] reports true for [ErrFormat].
//
// The `%w` verb does not work.
func parseErr(f string, v ...interface{}) error {
	return parseError(fmt.Sprintf(f, v...))
}

// ParseError is the concrete type out of [parseErr].
type parseError string

func (e parseError) Is(tgt error) bool { return tgt == ErrFormat }
func (e parseError) Error() string     { return string(e) }

// ErrFileNeeded is reported when an [os.File] is needed for buffering tar contents, but has not been provided.
var ErrFileNeeded = errors.New("tarfs: *os.File needed but not provided")

// BuildTOC builds a table of contents from the optionally-compressed bytes in the [io.ReaderAt] pointed to by r.
// Because we may have to decompress the bytes and have to do a linear read anyway, immediately buffer the contents.
//
// This passes the result back out to re-use the codepath for when the TOC is separable from the archive.
// The returned [os.File] is either "r" or "buf", depending on if "r" is backed by an [os.File].
func buildTOC(ctx context.Context, r io.ReaderAt, dec decompressor, buf *os.File) (*toc, *os.File, error) {
	_, span := tracer.Start(ctx, "buildTOC")
	defer span.End()
	// This copies the passed in bytes, optionally eliding the copy entirely if
	// an *os.File was passed in at the start.
	_, isFile := r.(*os.File)
	if !isFile && buf == nil {
		return nil, nil, ErrFileNeeded
	}

	var pos io.Seeker = buf
	var tr *tar.Reader
	switch {
	case dec != nil:
		if err := dec.Reset(io.NewSectionReader(r, 0, -1)); err != nil {
			return nil, nil, err
		}
		tr = tar.NewReader(io.TeeReader(dec, buf))
	case isFile:
		span.AddEvent("using ReaderAt directly")
		// Use the backing File directly.
		buf = r.(*os.File)
		pos = buf
		if _, err := pos.Seek(0, io.SeekStart); err != nil {
			return nil, nil, err
		}
		tr = tar.NewReader(buf)
	default:
		span.AddEvent("no decompression")
		tr = tar.NewReader(io.TeeReader(io.NewSectionReader(r, 0, -1), buf))
	}

	var toc toc
	toc.Version = 1
	toc.Entry = make([]Entry, 0, 4096) // Guess at initial capacity.
	h, err := tr.Next()
	for ; err == nil; h, err = tr.Next() {
		off, err := pos.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, nil, parseErr("tarfs: error reading header: %v", err)
		}
		// Turn the tar.Header into an Entry
		i := len(toc.Entry)
		toc.Entry = append(toc.Entry, Entry{})
		e := &toc.Entry[i]
		e.Offset = off
		// Copy everything over:
		e.Size = h.Size
		// Callee does path normalization.
		e.Name = h.Name
		e.Linkname = h.Linkname
		e.ModTime = h.ModTime
		e.AccessTime = h.AccessTime
		e.ChangeTime = h.ChangeTime
		e.UserName = h.Uname
		e.GroupName = h.Gname
		e.UID = h.Uid
		e.GID = h.Gid
		e.Mode = h.Mode
		e.Devmajor = h.Devmajor
		e.Devminor = h.Devminor
		switch h.Typeflag {
		case tar.TypeReg:
			e.Type = typeReg
		case tar.TypeLink:
			e.Type = typeHardlink
		case tar.TypeDir:
			e.Type = typeDir
			e.Mode |= int64(fs.ModeDir)
		case tar.TypeSymlink:
			e.Type = typeSymlink
			e.Mode |= int64(fs.ModeSymlink)
		case tar.TypeChar:
			e.Type = typeChar
			e.Mode |= int64(fs.ModeDevice)
			e.Mode |= int64(fs.ModeCharDevice)
		case tar.TypeBlock:
			e.Type = typeBlock
			e.Mode |= int64(fs.ModeDevice)
		case tar.TypeFifo:
			e.Type = typeFifo
			e.Mode |= int64(fs.ModeNamedPipe)
		default:
			return nil, nil, fmt.Errorf("tarfs: unknown kind: %v", h.Typeflag)
		}
	}
	if !errors.Is(err, io.EOF) {
		return nil, nil, parseErr("tarfs: error reading header: %v", err)
	}
	span.SetAttributes(attribute.Int("entries", len(toc.Entry)))

	return &toc, buf, nil
}

/*
NOTE(hank) The eStargz format differs from the stargz format in where the tar headers are placed relative to the gzip headers.
In stargz, the tar headers are inside the gzip header, so readers can extract individual members knowing only the offset.
The eStargz format implemented here has gzip headers "inside" the tar members, and so the length needs to be known beforehand.
This format results in every member having at least one extra tar block describing the next member, except for the first (just a header) and last (just data).
The TOC is specially defined to be a whole tar by itself.
The zstd chunked scheme is largely the same, but places the TOC in a skippable frame (a concept nonexistent in gzip) instead of as a tar member.
*/

// This limit copied out of the containers/storage code.
// 50MiB seems way too big but it's better than not having it.
// 🤷
const bufLimit = (1 << 20) * 50

// ExtractZstdTOC pulls the table of contents out of the skippable frame as indicated in the footer.
func extractZstdTOC(ctx context.Context, r io.ReaderAt, z *zstd.Decoder, footer []byte) (*toc, error) {
	const crfsKind = 1
	ctx, span := tracer.Start(ctx, "extractZstdTOC")
	defer span.End()

	var h zstd.Header
	if err := h.Decode(footer); err != nil {
		return nil, err
	}
	if !h.Skippable || h.SkippableID != 0 {
		return nil, parseErr("martian zstd frame")
	}
	if h.SkippableSize != 40 {
		return nil, parseErr("unexpected frame size")
	}

	b := footer[h.HeaderSize:]
	offset := int64(binary.LittleEndian.Uint64(b[0:8]))
	length := binary.LittleEndian.Uint64(b[8:16])
	if length > bufLimit {
		return nil, errors.New("manifest too big")
	}
	lengthUncompressed := binary.LittleEndian.Uint64(b[16:24])
	if lengthUncompressed > bufLimit {
		return nil, errors.New("manifest too big")
	}
	if kind := binary.LittleEndian.Uint64(b[24:32]); kind != crfsKind {
		return nil, parseErr("invalid manifest kind")
	}

	src, dst := make([]byte, length), make([]byte, 0, lengthUncompressed)
	n, err := r.ReadAt(src, offset)
	switch {
	case errors.Is(err, nil):
	case n == len(src) && errors.Is(err, io.EOF):
	default:
		return nil, fmt.Errorf("tarfs: unable to read manifest: %w", err)
	}

	dst, err = z.DecodeAll(src, dst)
	if err != nil {
		return nil, fmt.Errorf("tarfs: unable to decompress manifest: %w", err)
	}

	var toc toc
	if err := json.Unmarshal(dst, &toc); err != nil {
		return nil, fmt.Errorf("tarfs: unable to decode manifest: %w", err)
	}
	span.SetAttributes(attribute.Int("entries", len(toc.Entry)))
	return &toc, nil
}

// ExtractGzipTOC pulls the table of contents out of the tar archive as indicated in the footer.
func extractGzipTOC(ctx context.Context, r io.ReaderAt, z *gzip.Reader, footer []byte) (*toc, error) {
	ctx, span := tracer.Start(ctx, "extractGzipTOC")
	defer span.End()
	if err := z.Reset(bytes.NewReader(footer)); err != nil {
		return nil, err
	}

	b := z.Extra
	// The main deviation from the stargz footer is the addition of the following 4 bytes to make the extra data RFC1952 compliant.
	// The go "gzip" package doesn't bother with this framing, so that's probably where the initial (mis)use came from.
	if b[0] != 'S' || b[1] != 'G' ||
		binary.LittleEndian.Uint16(b[2:4]) != 22 ||
		!bytes.Equal(b[20:26], []byte("STARGZ")) {
		return nil, parseErr("invalid extra field")
	}
	offset, err := strconv.ParseInt(string(b[4:20]), 16, 64)
	if err != nil {
		return nil, parseErr("unable to parse offset: %v", err)
	}

	// Abuse a section reader to get a cursor over the ReaderAt.
	if err := z.Reset(io.NewSectionReader(r, offset, bufLimit)); err != nil {
		return nil, err
	}
	tr := tar.NewReader(z)
	h, err := tr.Next()
	switch {
	case err != nil:
		return nil, err
	case h.Name != `stargz.index.json`:
		return nil, parseErr("found unexpected file: %v", h.Name)
	}

	var toc toc
	if err := json.NewDecoder(tr).Decode(&toc); err != nil {
		return nil, fmt.Errorf("tarfs: unable to decode manifest: %w", err)
	}
	span.SetAttributes(attribute.Int("entries", len(toc.Entry)))
	return &toc, nil
}
