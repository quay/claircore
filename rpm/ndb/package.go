package ndb

import (
	"context"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
)

// Pages are hard-coded to 4096 bytes for the Package database; this
// is different from the Index database, which could have variable page
// sizes.

// PackageDB is the "pkgdb" a.k.a. "Packages.db", the raw package data.
type PackageDB struct {
	r      io.ReaderAt
	lookup map[uint32]*pkgSlot
	slot   []pkgSlot
	pkgHeader
}

// Parse closes over the provided [io.ReaderAt] and populates the provided PackageDB.
func (db *PackageDB) Parse(r io.ReaderAt) error {
	const (
		headerSz = 4 * 8
		pageSz   = 4096
	)

	// Read and verify the header.
	b := make([]byte, headerSz)
	if _, err := r.ReadAt(b, 0); err != nil {
		return fmt.Errorf("ndb: package: unable to read header: %w", err)
	}
	if err := db.pkgHeader.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("ndb: package: unable to unmarshal header: %w", err)
	}

	// Package count should be contiguous.
	ct := int(db.NextPkgIdx - 1)
	db.lookup = make(map[uint32]*pkgSlot, ct)
	db.slot = make([]pkgSlot, 0, ct)
	b = b[:slotSize]
	// Read every populated slot (these should be contiguous) and populate the lookup table.
	for i, off := 0, int64(slotStart*slotSize); i < ct; i, off = i+1, off+slotSize {
		if _, err := r.ReadAt(b, off); err != nil {
			return fmt.Errorf("ndb: package: unable to read slot %d: %w", i, err)
		}
		db.slot = append(db.slot, pkgSlot{})
		x := &db.slot[i]
		if err := x.UnmarshalBinary(b); err != nil {
			return fmt.Errorf("ndb: package: slot %d: unexpected error: %w", i, err)
		}
		db.lookup[x.Index] = x
	}
	db.r = r

	return nil
}

// AllHeaders returns ReaderAts for all RPM headers in the PackageDB.
func (db *PackageDB) AllHeaders(_ context.Context) ([]io.ReaderAt, error) {
	r := make([]io.ReaderAt, int(db.NextPkgIdx)-1)
	var err error
	for i := uint32(1); i < db.NextPkgIdx && err == nil; i++ {
		r[int(i-1)], err = db.GetHeader(i)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// GetHeader returns an [io.ReaderAt] populated with [rpm.Header] data or
// reports an error.
func (db *PackageDB) GetHeader(pkgID uint32) (io.ReaderAt, error) {
	const (
		headerSize  = 4 * 4
		trailerSize = 4 * 3
	)
	// Lookup offset and count.
	blob, ok := db.lookup[pkgID]
	if !ok {
		return nil, fmt.Errorf("ndb: package: package id %d does not exist", pkgID)
	}

	// Read and verify header.
	b := make([]byte, headerSize)
	if _, err := db.r.ReadAt(b, blob.Offset()); err != nil {
		return nil, fmt.Errorf("ndb: package: error reading header: %w", err)
	}
	var bh blobHeader
	if err := bh.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("ndb: package: bad header: %w", err)
	}
	if bh.Package != pkgID {
		return nil, fmt.Errorf("ndb: package: martian blob")
	}

	// Read and verify trailer.
	if _, err := db.r.ReadAt(b[:trailerSize], blob.Offset()+blob.Count()-trailerSize); err != nil {
		return nil, fmt.Errorf("ndb: package: error reading trailer: %w", err)
	}
	var bt blobTrailer
	if err := bt.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("ndb: package: bad trailer: %w", err)
	}
	if bt.Len != bh.Len {
		return nil, fmt.Errorf("ndb: package: header/trailer length mismatch")
	}
	// This is slightly different from the ultimate reader -- the checksum includes any padding.
	h := adler32.New()
	rd := io.NewSectionReader(db.r, blob.Offset(), blob.Count()-trailerSize)
	if _, err := io.Copy(h, rd); err != nil {
		panic(err)
	}
	if got, want := h.Sum32(), bt.Checksum; got != want {
		return nil, fmt.Errorf("ndb: package: checksum mismatch; got: 0x%08x, want: 0x%08x", got, want)
	}

	return io.NewSectionReader(db.r, blob.Offset()+headerSize, int64(bh.Len)), nil
}

// PkgHeader is the header for the PackageDB. It's meant to be embedded.
type pkgHeader struct {
	Generation uint32
	NPages     uint32
	NextPkgIdx uint32
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for a PackageDB header.
func (h *pkgHeader) UnmarshalBinary(b []byte) error {
	const (
		magic   = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
		version = 0

		magicOffset        = 0
		versionOffset      = 4
		generationOffset   = 8
		nPagesOffset       = 12
		nextPkgIndexOffset = 16
	)
	if len(b) < 32 {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[magicOffset:]) != magic {
		return fmt.Errorf("ndb: package: bad header: bad magic")
	}
	if le.Uint32(b[versionOffset:]) != version {
		return fmt.Errorf("ndb: package: bad header: bad version")
	}

	h.Generation = le.Uint32(b[generationOffset:])
	h.NPages = le.Uint32(b[nPagesOffset:])
	h.NextPkgIdx = le.Uint32(b[nextPkgIndexOffset:])

	return nil
}

// PkgSlot is a decoded package slot.
type pkgSlot struct {
	Index     uint32
	blkOffset uint32
	blkCount  uint32
}

// BlockSize is the size of a blob block.
//
// Blobs are denominated and allocated in blocks.
const blockSize = 16

func (s *pkgSlot) GoString() string {
	return fmt.Sprintf("blob@%08x[%08x]", s.blkOffset*blockSize, s.blkCount*blockSize)
}

// Offset reports the byte offset indicated by the slot.
func (s *pkgSlot) Offset() int64 { return int64(s.blkOffset) * blockSize }

// Count reports the length in bytes of the data in the slot.
func (s *pkgSlot) Count() int64 { return int64(s.blkCount) * blockSize }

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *pkgSlot) UnmarshalBinary(b []byte) error {
	const (
		magic = ('S' | 'l'<<8 | 'o'<<16 | 't'<<24)

		magicOffset      = 0
		slotIdxOffset    = 4
		slotOffsetOffset = 8
		slotCountOffset  = 12

		headerSize  = 4 * 4
		trailerSize = 3 * 4
	)
	if len(b) < slotSize {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[magicOffset:]) != magic {
		return fmt.Errorf("slot: bad magic")
	}
	s.Index = le.Uint32(b[slotIdxOffset:])
	s.blkOffset = le.Uint32(b[slotOffsetOffset:])
	s.blkCount = le.Uint32(b[slotCountOffset:])
	// Double-check the blob size.
	if s.blkCount < ((headerSize + trailerSize + blockSize - 1) / blockSize) {
		return fmt.Errorf("slot: nonsense block count (%d)", s.blkCount)
	}

	return nil
}

// BlobHeader is the header for a blob.
type blobHeader struct {
	Package    uint32
	Generation uint32
	Len        uint32
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (h *blobHeader) UnmarshalBinary(b []byte) error {
	const (
		magic   = ('B' | 'l'<<8 | 'b'<<16 | 'S'<<24)
		minSize = 4 * 4

		offsetMagic      = 0
		offsetPackage    = 4
		offsetGeneration = 8
		offsetLength     = 12
	)

	if len(b) < minSize {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[offsetMagic:]) != magic {
		return errors.New("blob: header: bad magic")
	}
	h.Package = le.Uint32(b[offsetPackage:])
	h.Generation = le.Uint32(b[offsetGeneration:])
	h.Len = le.Uint32(b[offsetLength:])

	return nil
}

// BlockCount reports the number of 16-byte blocks this blob occupies.
func (h *blobHeader) BlockCount() uint32 {
	const (
		headerSize  = 4 * 4
		trailerSize = 3 * 4
	)
	return ((headerSize + h.Len + trailerSize + blockSize) - 1) / blockSize
}

// BlobTrailer is the trailer (a.k.a. "tail") of a blob.
type blobTrailer struct {
	Checksum uint32
	Len      uint32
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (t *blobTrailer) UnmarshalBinary(b []byte) error {
	const (
		magic   = ('B' | 'l'<<8 | 'b'<<16 | 'E'<<24)
		minSize = 3 * 4

		offsetChecksum = 0
		offsetLength   = 4
		offsetMagic    = 8
	)

	if len(b) < minSize {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[offsetMagic:]) != magic {
		return errors.New("blob: trailer: bad magic")
	}
	t.Checksum = le.Uint32(b[offsetChecksum:])
	t.Len = le.Uint32(b[offsetLength:])
	return nil
}
