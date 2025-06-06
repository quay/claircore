package bdb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/quay/zlog"
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
	if db.m.Type != pagetypeHashMeta {
		return fmt.Errorf("bdb: nonsense page type: %08x", db.m.Type)
	}
	if db.m.EncryptAlg != 0 { // none
		return errors.New("bdb: database encryption not supported")
	}
	ok := false
	for i := 0; i < 8; i++ {
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
  This package ignores it.

Note that the page type always falls in byte 25 -- very clever.
Don't freak out if it looks like the first page is read multiple ways; it is.

See also: libdb's src/dbinc/db_page.h
*/

// Meta is the generic metadata, aka DBMETA in C.
type meta struct {
	LSN         [8]byte  /* 00-07: LSN. */
	PageNo      uint32   /* 08-11: Current page number. */
	Magic       uint32   /* 12-15: Magic number. */
	Version     uint32   /* 16-19: Version. */
	PageSize    uint32   /* 20-23: Pagesize. */
	EncryptAlg  byte     /*    24: Encryption algorithm. */
	Type        byte     /*    25: Page type. */
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

// Pagetype numbers:
const (
	pagetypeHashMeta     = 8
	pagetypeHashUnsorted = 2
	pagetypeHash         = 13
	pagetypeHashOffIndex = 3
	pagetypeOverflow     = 7
	pagetypeKeyData      = 1 // Disused, we never examine the keys.
)

// Serialized sizes:
const (
	hashpageSize    = 26
	hashoffpageSize = 12
)

// Hash database metadata, aka HMETA in C.
type hashmeta struct {
	meta                   /* 00-71: Generic meta-data page header. */
	MaxBucket   uint32     /* 72-75: ID of Maximum bucket in use */
	HighMask    uint32     /* 76-79: Modulo mask into table */
	LowMask     uint32     /* 80-83: Modulo mask into table lower half */
	FllFactor   uint32     /* 84-87: Fill factor */
	NElem       uint32     /* 88-91: Number of keys in hash table */
	HashCharKey uint32     /* 92-95: Value of hash(CHARKEY) */
	_           [32]uint32 /* 96-223: Spare pages for overflow */
	_           [59]uint32 /* 224-459: Unused space */
	CryptoMagic uint32     /* 460-463: Crypto magic number */
	_           [3]uint32  /* 464-475: Trash space - Do not use */
	// The comments don't line up, but the numbers come from the source, so...
	IV       [16]byte /* 476-495: Crypto IV */
	Checksum [20]byte /* 496-511: Page chksum */
}

// Hash page header, aka PAGE in C.
//
// Also shared with btree databases, which are unimplemented here.
// The [meta.PageSize] block of memory has this struct at position 0, then
// populates it backwards from the end for structured data, or immediately after
// this for binary data.
type hashpage struct {
	LSN            [8]byte /* 00-07: Log sequence number. */
	PageNo         uint32  /* 08-11: Current page number. */
	PrevPageNo     uint32  /* 12-15: Previous page number. */
	NextPageNo     uint32  /* 16-19: Next page number. */
	Entries        uint16  /* 20-21: Number of items on the page. */
	HighFreeOffset uint16  /* 22-23: High free byte page offset. */
	Level          byte    /*    24: Btree tree level. */
	Type           byte    /*    25: Page type. */
}

// Hash page entries.
//
// This data structure doesn't appear directly in the C source, but open a file
// in a hex editor and it's apparent. The comments mention that "For hash and
// btree leaf pages, index items are paired, e.g., inp[0] is the key for
// inp[1]'s data." I think this is just a codification of that.
//
// We never bother looking up the key. If access to a single, specific header
// were needed, the code would have to handle it then.
type hashentry struct {
	Key  uint16
	Data uint16
}

// Hash offpage header, aka HOFFPAGE in C.
//
// This stores the data on how to extract "overflow"/"offpage" data.
type hashoffpage struct {
	Type   byte    /*    00: Page type and delete flag. */
	_      [3]byte /* 01-03: Padding, unused. */
	PageNo uint32  /* 04-07: Offpage page number. */
	Length uint32  /* 08-11: Total length of item. */
}

// Headers returns an iterator over all RPM headers in the PackageDB.
func (db *PackageDB) Headers(ctx context.Context) iter.Seq2[io.ReaderAt, error] {
	pageSz := int64(db.m.PageSize)
	return func(yield func(io.ReaderAt, error) bool) {
		for n, lim := int64(0), int64(db.m.LastPageNo)+1; n < lim; n++ {
			pg := io.NewSectionReader(db.r, n*pageSz, pageSz)
			var h hashpage
			if err := binary.Read(pg, db.ord, &h); err != nil {
				if !yield(nil, fmt.Errorf("bdb: error reading hashpage: %w", err)) {
					return
				}
			}
			if h.Type != pagetypeHashUnsorted && h.Type != pagetypeHash {
				continue
			}
			if h.Entries%2 != 0 {
				if !yield(nil, errors.New("bdb: odd number of entries")) {
					return
				}
			}

			ent := make([]hashentry, int(h.Entries)/2)
			for i := range ent {
				if err := binary.Read(pg, db.ord, &ent[i]); err != nil {
					if !yield(nil, fmt.Errorf("bdb: error reading hash entry: %w", err)) {
						return
					}
				}
			}

			k := []byte{0x00}
			for _, e := range ent {
				off := int64(e.Data)
				// First, check what kind of hash entry this is.
				view := io.NewSectionReader(pg, off, hashoffpageSize)
				if _, err := view.ReadAt(k, 0); err != nil {
					if !yield(nil, fmt.Errorf("bdb: error peeking page type: %w", err)) {
						return
					}
				}
				if k[0] != pagetypeHashOffIndex {
					continue
				}
				// Read the page header, now that we know it's correct.
				var offpg hashoffpage
				if err := binary.Read(view, db.ord, &offpg); err != nil {
					if !yield(nil, fmt.Errorf("bdb: error reading hashoffpage: %w", err)) {
						return
					}
				}
				var r rope
				for n := offpg.PageNo; n != 0; {
					off := pageSz * int64(n)
					pg := io.NewSectionReader(db.r, off, pageSz)
					var h hashpage
					if err := binary.Read(pg, db.ord, &h); err != nil {
						if !yield(nil, fmt.Errorf("bdb: error reading hashpage: %w", err)) {
							return
						}
					}
					if h.Type != pagetypeOverflow {
						continue
					}
					off += hashpageSize

					var data *io.SectionReader
					if h.NextPageNo == 0 {
						// If this is the last page, only read to the end.
						data = io.NewSectionReader(db.r, off, int64(h.HighFreeOffset))
					} else {
						data = io.NewSectionReader(db.r, off, pageSz-hashpageSize)
					}
					if err := r.add(data); err != nil {
						if !yield(nil, fmt.Errorf("bdb: error adding to rope: %w", err)) {
							return
						}
					}
					n = h.NextPageNo
				}
				// Double-check we'll read the intended amount.
				if got, want := r.Size(), int64(offpg.Length); got != want {
					zlog.Info(ctx).
						Int64("got", got).
						Int64("want", want).
						Msg("bdb: expected data length botch")
				}

				if !yield(&r, nil) {
					return
				}
			}
		}
	}
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
				continue
			}
			fallthrough
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
