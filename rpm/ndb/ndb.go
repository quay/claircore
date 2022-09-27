package ndb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/quay/claircore/rpm/internal/rpm"
)

var le = binary.LittleEndian

// Used throughout the various DBs.
const (
	slotSize  = 4 * 4
	slotStart = 2
)

// CheckMagic reports whether the Reader starts with a magic header for
// a file format supported by this package.
func CheckMagic(ctx context.Context, r io.Reader) bool {
	const (
		xdb = 'R' | 'p'<<8 | 'm'<<16 | 'X'<<24
		pkg = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	)
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return false
	}
	m := le.Uint32(b)
	return m == xdb || m == pkg
}

// XDB is the "xdb" a.k.a. "Index.db", the ndb mechanism for creating indexes.
type XDB struct {
	r      io.ReaderAt
	lookup map[rpm.Tag]*xdbSlot
	slot   []xdbSlot
	xdbHeader
}

// Parse closes over the passed [io.ReaderAt] and populates the XDB.
func (db *XDB) Parse(r io.ReaderAt) error {
	const headerSize = 32
	h := make([]byte, headerSize)
	if _, err := r.ReadAt(h, 0); err != nil {
		return fmt.Errorf("xdb: unable to read header: %w", err)
	}
	if err := db.xdbHeader.UnmarshalBinary(h); err != nil {
		return fmt.Errorf("xdb: bad header: %w", err)
	}
	pg := make([]byte, db.PageSize*db.SlotNPages)
	if _, err := r.ReadAt(pg, 0); err != nil {
		return fmt.Errorf("xdb: unable to read slots: %w", err)
	}

	// Size for full pages of slots.
	max := (len(pg) / slotSize) - slotStart
	db.lookup = make(map[rpm.Tag]*xdbSlot, max)
	db.slot = make([]xdbSlot, max)
	n := 0
	var x *xdbSlot
	for off := slotStart * slotSize; n < max; n, off = n+1, off+slotSize {
		x = &db.slot[n]
		if err := x.UnmarshalBinary(pg[off:]); err != nil {
			return err
		}
		if x.Tag == 0 || x.Tag == rpm.TagInvalid {
			break
		}
		db.lookup[x.Tag] = x
	}
	db.slot = db.slot[:n]
	db.r = r
	return nil
}

// Index reports the index for the specifed tag.
func (db *XDB) Index(tag rpm.Tag) (*Index, error) {
	slot, ok := db.lookup[tag]
	if !ok {
		return nil, fmt.Errorf("ndb: no such tag %d", tag)
	}
	off, ct := int64(slot.StartPage*db.PageSize), int64(slot.PageCount*db.PageSize)
	r := io.NewSectionReader(db.r, off, ct)
	var idx Index
	if err := idx.Parse(r); err != nil {
		return nil, err
	}
	return &idx, nil
}

type xdbHeader struct {
	Version        uint32
	Generation     uint32
	SlotNPages     uint32
	PageSize       uint32
	UserGeneration uint32
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for the xdb header.
func (h *xdbHeader) UnmarshalBinary(b []byte) error {
	const (
		headerSz = 32
		magic    = 'R' | 'p'<<8 | 'm'<<16 | 'X'<<24
		version  = 0

		offsetMagic          = 0
		offsetVersion        = 4
		offsetGeneration     = 8
		offsetSlotNPages     = 12
		offsetPageSize       = 16
		offsetUserGeneration = 20
	)

	if len(b) < headerSz {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[offsetMagic:]) != magic {
		return errors.New("xdb: bad magic")
	}
	h.Version = le.Uint32(b[offsetVersion:])
	if h.Version != version {
		return errors.New("bad version")
	}
	h.Generation = le.Uint32(b[offsetGeneration:])
	h.SlotNPages = le.Uint32(b[offsetSlotNPages:])
	h.PageSize = le.Uint32(b[offsetPageSize:])
	h.UserGeneration = le.Uint32(b[offsetUserGeneration:])
	return nil
}

type xdbSlot struct {
	Subtag    uint8
	Tag       rpm.Tag
	StartPage uint32
	PageCount uint32
}

func (s *xdbSlot) UnmarshalBinary(b []byte) error {
	const (
		magic     = ('S' | 'l'<<8 | 'o'<<16 | 0x00<<24)
		magicMask = ^uint32(0xFF << 24)

		magicOffset  = 0
		subtagOffset = 3
		tagOffset    = 4
		startOffset  = 8
		countOffset  = 12
	)
	if len(b) < slotSize {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[magicOffset:])&magicMask != magic {
		return fmt.Errorf("slot: bad magic")
	}
	s.Subtag = b[subtagOffset]
	s.Tag = rpm.Tag(le.Uint32(b[tagOffset:]))
	s.StartPage = le.Uint32(b[startOffset:])
	s.PageCount = le.Uint32(b[countOffset:])
	return nil
}
