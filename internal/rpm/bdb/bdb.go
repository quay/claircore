package bdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"math/bits"
)

// PackageDB is the "pkgdb" a.k.a. "Packages", the raw package data.
type PackageDB struct {
	r   io.ReaderAt
	ord binary.ByteOrder
	m   hashmeta
}

// Parse closes over the provided [io.ReaderAt] and readies the provided PackageDB.
func (db *PackageDB) Parse(r io.ReaderAt) error {
	const (
		hashmagic   = 0x00061561
		hashmagicBE = 0x61150600
	)
	db.ord = binary.LittleEndian
Again:
	pg := io.NewSectionReader(r, 0, 512)
	if err := binary.Read(pg, db.ord, &db.m); err != nil {
		return err
	}
	if db.m.Magic == hashmagicBE {
		// Swap, try again.
		db.ord = binary.BigEndian
		goto Again
	}

	if db.m.Magic != hashmagic {
		return fmt.Errorf("bdb: nonsense magic: %08x", db.m.Magic)
	}
	if db.m.Type != PageTypeHashMeta {
		return fmt.Errorf("bdb: nonsense page type: %08x", db.m.Type)
	}
	if db.m.EncryptAlg != 0 { // none
		return errors.New("bdb: database encryption not supported")
	}
	ok := false
	for i := range 8 {
		var sz uint32 = (1 << i) * 512
		if db.m.PageSize == sz {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("bdb: nonsense page size: %d", db.m.PageSize)
	}

	db.r = r
	return nil
}

/*
Some terminology:

- LSN:
  Log Sequence Number -- Needed for detecting stale writes, I think.
  This package just checks that it's consistent.

Note that the page type always falls in byte 25 -- very clever.

The C implementation uses a lot of pointer arithmetic on a mapped buffer.
This implementation uses a lot of io.SectionReaders.

See also: libdb's src/dbinc/db_page.h, src/dbinc/hash.h
*/

// Meta is the generic metadata, aka DBMETA in C.
type meta struct {
	LSN         uint64   /* 00-07: LSN. */
	PageNo      uint32   /* 08-11: Current page number. */
	Magic       uint32   /* 12-15: Magic number. */
	Version     uint32   /* 16-19: Version. */
	PageSize    uint32   /* 20-23: Pagesize. */
	EncryptAlg  byte     /*    24: Encryption algorithm. */
	Type        PageType /*    25: Page type. */
	Metaflags   byte     /* 26: Meta-only flags */
	_           byte     /* 27: Unused. */
	Free        uint32   /* 28-31: Free list page number. */
	LastPageNo  uint32   /* 32-35: Page number of last page in db. */
	NParts      uint32   /* 36-39: Number of partitions. */
	KeyCount    uint32   /* 40-43: Cached key count. */
	RecordCount uint32   /* 44-47: Cached record count. */
	Flags       uint32   /* 48-51: Flags: unique to each AM. */
	UID         [20]byte /* 52-71: Unique file ID. */
}

// Serialized sizes:
const (
	pageSize = 26
)

// Hash database metadata, aka HMETA in C.
type hashmeta struct {
	meta                     /* 00-71: Generic meta-data page header. */
	MaxBucket     uint32     /* 72-75: ID of Maximum bucket in use */
	HighMask      uint32     /* 76-79: Modulo mask into table */
	LowMask       uint32     /* 80-83: Modulo mask into table lower half */
	FllFactor     uint32     /* 84-87: Fill factor */
	NElem         uint32     /* 88-91: Number of keys in hash table */
	HashCharKey   uint32     /* 92-95: Value of hash(CHARKEY) */
	Spares        [32]uint32 /* 96-223: Spare pages for overflow */
	BlobThreshold uint32     /* 224-227: Minimum blob file size. */
	BlobFileLo    uint32     /* 228-231: Blob file dir id lo. */
	BlobFileHi    uint32     /* 232-235: Blob file dir id hi. */
	BlobSdbLo     uint32     /* 236-239: Blob sdb dir id lo. */
	BlobSdbHi     uint32     /* 240-243: Blob sdb dir id hi. */
	_             [54]uint32 /* 244-459: Unused space */
	CryptoMagic   uint32     /* 460-463: Crypto magic number */
	_             [3]uint32  /* 464-475: Trash space - Do not use */
	IV            [16]byte   /* 476-495: Crypto IV */
	Checksum      [20]byte   /* 496-511: Page chksum */
}

// Hash page header
//
// This is the C PAGE, renamed for how the fields are used.
//
// Also shared with btree databases, which are unimplemented here.
// The [meta.PageSize] block of memory has this struct at position 0, then
// populates it backwards from the end for structured data, or immediately after
// this for binary data.
type hashpage struct {
	LSN        uint64   /* 00-07: Log sequence number. */
	PageNo     uint32   /* 08-11: Current page number. */
	PrevPageNo uint32   /* 12-15: Previous page number. */
	NextPageNo uint32   /* 16-19: Next page number. */
	Entries    uint16   /* 20-21: Number of items on the page. */
	_          uint16   /* 22-23: High free byte page offset. */
	_          byte     /*    24: Btree tree level. */
	Type       PageType /*    25: Page type. */
}

// Overflow page header.
//
// This is the C PAGE, renamed for how fields are used.
type overflowpage struct {
	LSN        uint64   /* 00-07: Log sequence number. */
	PageNo     uint32   /* 08-11: Current page number. */
	PrevPageNo uint32   /* 12-15: Previous page number. */
	NextPageNo uint32   /* 16-19: Next page number. */
	_          uint16   /* 20-21: Number of items on the page. */
	Length     uint16   /* 22-23: High free byte page offset. Interpreted as length for overflow page.*/
	_          byte     /*    24: Btree tree level. */
	Type       PageType /*    25: Page type. */
}

// Hash offpage header, aka HOFFPAGE in C.
//
// This stores the data on how to extract "overflow"/"offpage" data.
type hashoffpage struct {
	Type   HashPageType /*    00: Page type and delete flag. */
	_      [3]byte      /* 01-03: Padding, unused. */
	PageNo uint32       /* 04-07: Offpage page number. */
	Length uint32       /* 08-11: Total length of item. */
}

// UnimplementedPageError is reported when the page handling hits a type not
// implemented yet.
type unimplementedPageError struct {
	Kind HashPageType
}

// Error implements [error].
func (e *unimplementedPageError) Error() string {
	return fmt.Sprintf("bdb: unimplemented hash page type: %v", e.Kind)
}

// UnknownPageType constructs an [unimplementedPageError].
func unknownPageType(k HashPageType) *unimplementedPageError {
	return &unimplementedPageError{Kind: k}
}

// Sentinel errors for unimplemented parts:
var (
	ErrHashPageDuplicate error = unknownPageType(HashPageTypeDuplicate)
	ErrHashPageOffDup    error = unknownPageType(HashPageTypeOffDup)
	ErrHashPageBlob      error = unknownPageType(HashPageTypeBlob)
)

// Headers returns an iterator over all RPM headers in the PackageDB.
func (db *PackageDB) Headers(_ context.Context) iter.Seq2[io.ReaderAt, error] {
	return func(yield func(io.ReaderAt, error) bool) {
		// For peeking at the interior page type.
		peek := make([]byte, 1)
		// Can ignore keys once we've seen the zero key.
		// This should be per-db (not per-page), so is hoisted out here.
		var seenZeroKey bool
		var pg *io.SectionReader

	HandlePage:
		for pg = range db.rootPages() {
			for pg != nil {
				h, err := db.readHashpage(pg)
				if err != nil {
					if !yield(nil, err) {
						return
					}
					continue HandlePage
				}
				// Decode all the entry offsets immediately, because they'll be
				// needed for calculating entry lengths in some cases.
				entOffs := make([]uint16, int(h.Entries))
				if err := binary.Read(pg, db.ord, entOffs); err != nil {
					if !yield(nil, fmt.Errorf("bdb: error reading hash entry pointer: %w", err)) {
						return
					}
					continue HandlePage
				}

			HandleEntry:
				// Don't do an int range so that the code can skip uninteresting
				// pairs.
				for i := 0; i < int(h.Entries); i++ {
					isKey := (i & 1) == 0
					if isKey && seenZeroKey {
						continue HandleEntry
					}

					off := int64(entOffs[i])
					if _, err := pg.Seek(off, io.SeekStart); err != nil {
						if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
							return
						}
						continue HandleEntry
					}
					if _, err := pg.Read(peek); err != nil {
						if !yield(nil, fmt.Errorf("bdb: error reading hash entry pointer: %w", err)) {
							return
						}
						continue HandleEntry
					}
					if _, err := pg.Seek(-1, io.SeekCurrent); err != nil {
						if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
							return
						}
						continue HandleEntry
					}

					// Handle the HashPage per-type:
					typ := HashPageType(peek[0])
					switch typ {
					case HashPageTypeKeyData:
						// Read the variable-length data into a buffer.
						var itemLen int64
						if i == 0 {
							itemLen = int64(db.m.PageSize) - off
						} else {
							itemLen = int64(entOffs[i-1]) - off
						}
						var buf bytes.Buffer
						buf.Grow(int(itemLen))
						if _, err := io.CopyN(&buf, pg, itemLen); err != nil {
							if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
								return
							}
							continue HandleEntry
						}
						// Skip over "type".
						if _, err := buf.ReadByte(); err != nil {
							if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
								return
							}
							continue HandleEntry
						}

						switch {
						case isKey && bytes.Equal(buf.Bytes(), zeroKey):
							// Skip the value stored at the zeroKey.
							seenZeroKey = true
							i++
							fallthrough
						case isKey:
							continue HandleEntry
						default:
							// Otherwise, return this buffer
							if !yield(bytes.NewReader(buf.Bytes()), nil) {
								return
							}
						}

					case HashPageTypeOffpage:
						var hoff hashoffpage
						if err := binary.Read(pg, db.ord, &hoff); err != nil {
							if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
								return
							}
							continue HandleEntry
						}
						r, err := db.overflow(hoff.PageNo)
						if err != nil {
							if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
								return
							}
							continue HandleEntry
						}
						if !yield(r, err) {
							return
						}
					case HashPageTypeDuplicate:
						if !yield(nil, ErrHashPageDuplicate) {
							return
						}
					case HashPageTypeOffDup:
						if !yield(nil, ErrHashPageOffDup) {
							return
						}
					case HashPageTypeBlob:
						if !yield(nil, ErrHashPageBlob) {
							return
						}
					default:
						if !yield(nil, unknownPageType(typ)) {
							return
						}
					}
				}

				// Load to next page if needed.
				if h.NextPageNo == 0 {
					pg = nil
				} else {
					pg = db.page(h.NextPageNo)
				}
			}
		}
	}
}

// ZeroKey is an all-zeroes key. This seems to contain the number of hash
// keys.
var zeroKey = []byte{0, 0, 0, 0}

// Pageoffset calculates the absolute offset for the numbered page.
func (db *PackageDB) pageoffset(pageno uint32) int64 {
	return int64(pageno) * int64(db.m.PageSize)
}

// Page returns a reader for the numbered page.
func (db *PackageDB) page(pageno uint32) *io.SectionReader {
	return io.NewSectionReader(db.r, db.pageoffset(pageno), int64(db.m.PageSize))
}

// BucketToPage returns a reader for the initial page of the numbered bucket.
func (db *PackageDB) bucketToPage(b uint32) *io.SectionReader {
	pn := uint32(b) + db.m.Spares[bits.Len32(b)]
	return db.page(pn)
}

// RootPages iterates over the root pages of all the buckets in the database.
func (db *PackageDB) rootPages() iter.Seq[*io.SectionReader] {
	return func(yield func(*io.SectionReader) bool) {
		for bn := range db.m.MaxBucket + 1 {
			if !yield(db.bucketToPage(bn)) {
				return
			}
		}
	}
}

// These "readpage" methods can't be a generic function because of checking the
// LSN and type.

// ReadHashpage reads a [hashpage] header from the supplied [io.SectionReader].
func (db *PackageDB) readHashpage(pg *io.SectionReader) (hashpage, error) {
	var h hashpage
	if err := binary.Read(pg, db.ord, &h); err != nil {
		return h, fmt.Errorf("bdb: error reading hashpage: %w", err)
	}
	if got, want := h.LSN, db.m.LSN; got != want {
		return h, fmt.Errorf("bdb: stale lsn: %016x != %016x", got, want)
	}
	if got, want := h.Type, PageTypeHash; got != want {
		return h, fmt.Errorf("bdb: unexpected page type: %v != %v", got, want)
	}
	return h, nil
}

// ReadOverflowpage reads an [overflowpage] header from the supplied [io.SectionReader].
func (db *PackageDB) readOverflowpage(pg *io.SectionReader) (overflowpage, error) {
	var ov overflowpage
	if err := binary.Read(pg, db.ord, &ov); err != nil {
		return ov, fmt.Errorf("bdb: error reading overflowpage: %w", err)
	}
	if got, want := ov.LSN, db.m.LSN; got != want {
		return ov, fmt.Errorf("bdb: stale lsn: %016x != %016x", got, want)
	}
	if got, want := ov.Type, PageTypeOverflow; got != want {
		return ov, fmt.Errorf("bdb: unexpected page type: %v != %v", got, want)
	}
	return ov, nil
}

// Overflow returns a [rope] reading the data from one or more Overflow pages.
func (db *PackageDB) overflow(start uint32) (*rope, error) {
	var r rope
	pgno := start
	for pgno != 0 {
		pg := db.page(pgno)
		ov, err := db.readOverflowpage(pg)
		if err != nil {
			return nil, err
		}
		data := io.NewSectionReader(db.r, db.pageoffset(ov.PageNo)+pageSize, int64(ov.Length))
		if err := r.add(data); err != nil {
			return nil, err
		}
		pgno = ov.NextPageNo
	}
	return &r, nil
}

// Rope provides an [io.ReaderAt] over an ordered slice of [io.ReaderAt].
//
// It's much simpler than a real rope because it's append only.
type rope struct {
	rd  []*io.SectionReader
	off []int64
}

var _ io.ReaderAt = (*rope)(nil)

// ReadAt implements [io.ReaderAt].
func (r *rope) ReadAt(b []byte, off int64) (int, error) {
	// Find start:
	idx := 0
	for i, roff := range r.off {
		if roff > off {
			break
		}
		idx = i
	}

	// Read as many segments as needed:
	n := 0
	rdoff := off - r.off[idx] // offset into the reader at "idx"
	for {
		rn, err := r.rd[idx].ReadAt(b[n:], rdoff)
		n += rn
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, io.EOF):
			idx++
			if idx != len(r.rd) {
				rdoff = 0 // Reading from the start, now that we're on the next one.
				break     // May return EOF or nil on an exact-sized read, so hit the post-switch check.
			}
			fallthrough
		// Don't need to handle non-EOF short reads because [io.ReaderAt] is documented
		// to error on short reads.
		default:
			return n, err
		}
		if n == len(b) {
			break
		}
	}
	return n, nil
}

// Size reports the total size of data that can be read from this rope.
func (r *rope) Size() (s int64) {
	for _, rd := range r.rd {
		s += rd.Size()
	}
	return s
}

// Add appends the provided [io.SectionReader].
func (r *rope) add(rd *io.SectionReader) error {
	var off int64
	for _, rd := range r.rd {
		off += rd.Size()
	}
	r.rd = append(r.rd, rd)
	r.off = append(r.off, off)
	return nil
}
