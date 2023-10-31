package tarfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/semaphore"
)

// DiskBuf encapsulates all the logic for random access and decompression from
// an upstream [io.ReaderAt] into a locally-backed buffer.
type diskBuf struct {
	// All "buf" reads/writes are done by *At methods, meaning the file only needs
	// to be locked when resizing it.
	resizeMu sync.Mutex
	upstream io.ReaderAt
	dec      decompressor
	chunk    func(int) inode
	buf      *os.File
	sem      *semaphore.Weighted
}

// NewDiskBuf allocates a disk-backed buffer.
//
// The passed-in [os.File] is not closed with the diskBuf.
func newDiskBuf(r io.ReaderAt, z decompressor, chunk func(int) inode, spool *os.File) (*diskBuf, error) {
	d := diskBuf{
		upstream: r,
		dec:      z,
		chunk:    chunk,
		buf:      spool,
		sem:      semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0))),
	}
	return &d, nil
}

// FetchFile reads compressed data from the backing [io.ReaderAt] and decompresses
// it into a contiguous section of the backing buffer. The buffer has no maximum
// size and is never re-used; that is to say, the maximum size is about the same
// as if the data were downloaded and decompressed in its entirety.
//
// The buffering could be implemented a few different ways transparently:
//
//   - Each opened file could get its own backing file buffer that's removed once all
//     opened [fs.File] implementations for it are Closed.
//   - The backing file could be used as a ring buffer once it hits some size,
//     at the cost of inserting file headers and then needing to seek to the next open
//     section.
//   - The ring buffer idea could also shrink down, if a large file pushed it over
//     the target size and was then closed.
//
// All of these would require some reference counting and in the case of the ring-buffer,
// a scavenger routine to collapse and potentially move segments. The execution time
// may be able to be mitigated with fs-specific optimizations, but the need for any
// of these strategies should be demonstrated first.
//
// Multi-chunk files are handled transparently, but not implemented in the zstd:chunked
// format as implemented by the github.com/containers modules.
func (d *diskBuf) fetchFile(r inode) (off, sz int64, err error) {
	const op = `fetchfile`
	d.sem.Acquire(context.Background(), 1)
	defer d.sem.Release(1)

	// NB Weirdness for correct locking without extra scope.
	d.resizeMu.Lock()
	off, err = d.buf.Seek(0, io.SeekCurrent)
	if err == nil {
		err = d.buf.Truncate(off + int64(r.Entry.Size))
	}
	if err == nil {
		_, err = d.buf.Seek(0, io.SeekEnd)
	}
	d.resizeMu.Unlock()
	if err != nil {
		return -1, -1, &fs.PathError{
			Op:   op,
			Path: r.Name(),
			Err:  err,
		}
	}
	sz = int64(r.Entry.Size)

	fhash := io.Discard
	cksum, hasher, err := toCheck(r.Entry.Digest)
	// Any parse error from this optional property should be ignored.
	// Any use of "cksum" or "hasher" needs to be checked that they're
	// not nil.
	if err == nil {
		fhash = hasher
	}
	// From here on out, reset the file cursor on error cases.
	chunks := []inode{r}
	for _, ei := range r.chunk {
		chunks = append(chunks, d.chunk(ei))
	}

	// Using a bigger buffer here allows for the underlying ReaderAt to be
	// dumber. This is expected to be backed by making HTTP requests, where the
	// latency is much worse than disk. As such, it makes sense to do fewer,
	// bigger reads rather than many tiny reads. A bigger buffer here results
	// in bigger range requests to the underlying ReaderAt, and means it
	// (hopefully) won't need prefetching logic in an HTTP-backed
	// implementation.
	cp := getCopyBuf()
	defer putCopyBuf(cp)

	// This src, dst pair works by swapping out what compressed bytes are being
	// fed into the decoder. Every chunk resets the reader to pull from a new
	// section of compressed source, then opportunistically validates the
	// decompressed data chunk-wise.
	src := io.TeeReader(io.LimitReader(d.dec, sz), fhash)
	dst := io.NewOffsetWriter(d.buf, off)
	for n, e := range chunks {
		zsrc := io.NewSectionReader(d.upstream, e.Offset, -1) // abuse a section reader to get a cursor
		if err := d.dec.Reset(zsrc); err != nil {
			return -1, -1, &fs.PathError{
				Op:   op,
				Path: r.Name(),
				Err:  err,
			}
		}
		hasher := io.Discard
		cksum, hash, err := toCheck(e.ChunkDigest)
		if err == nil { // Zstd:chunked doesn't treat this as a mandatory property.
			hasher = hash
		}
		if _, err := io.CopyBuffer(dst, io.TeeReader(src, hasher), cp); err != nil {
			return -1, -1, &fs.PathError{
				Op:   op,
				Path: r.Name(),
				Err:  err,
			}
		}
		if cksum != nil && !bytes.Equal(cksum, hash.Sum(nil)) {
			return -1, -1, &fs.PathError{
				Op:   op,
				Path: r.Name(),
				Err: fmt.Errorf("failed to validate chunk %d: got: %q, want: %q",
					n, hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(cksum)),
			}
		}
	}

	if cksum != nil && !bytes.Equal(cksum, hasher.Sum(nil)) {
		return -1, -1, &fs.PathError{
			Op:   op,
			Path: r.Name(),
			Err: fmt.Errorf("failed to validate file: got: %q, want: %q",
				hex.EncodeToString(hasher.Sum(nil)), hex.EncodeToString(cksum)),
		}
	}

	return off, sz, nil
}

// Close puts decompressors back into their pools and closes the buffer file.
func (d *diskBuf) Close() error {
	switch z := d.dec.(type) {
	case *gzip.Reader:
		putGzip(z)
	case *zstd.Decoder:
		putZstd(z)
	default:
		panic(fmt.Sprintf("programmer error: unknown decompressor type %T", z))
	}
	return nil
}

// ToCheck takes an OCI-like digest string and returns the binary checksum and a
// hasher using the same algorithm.
func toCheck(d string) ([]byte, hash.Hash, error) {
	alg, enc, ok := strings.Cut(d, ":")
	if !ok {
		return nil, nil, fmt.Errorf("invalid digest %q", d)
	}
	var h hash.Hash
	switch alg {
	case `sha256`:
		h = sha256.New()
	case `sha512`:
		h = sha512.New()
	default:
		return nil, nil, fmt.Errorf("unknown algorithm: %q", alg)
	}
	b, err := hex.DecodeString(enc)
	if err != nil {
		return nil, nil, err
	}
	return b, h, nil
}
