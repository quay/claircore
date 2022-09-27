package ndb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Index is an index over an RPM tag.
type Index struct {
	// SlotSpace reads the slot section of the Index.
	slotSpace *io.SectionReader
	// KeySpace reads the key section of the Index.
	keySpace *io.SectionReader
	// HMask is the mask for hash keys.
	hMask uint32

	indexHeader
}

// IndexHeader is the header for a tag index. It's meant to be embedded.
type indexHeader struct {
	Generation uint32
	NSlots     uint32
	UsedSlots  uint32
	DummySlots uint32
	XMask      uint32
	KeyEnd     uint32
	KeyExcess  uint32
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for an Index header.
func (i *indexHeader) UnmarshalBinary(b []byte) error {
	const (
		magic   = ('R' | 'p'<<8 | 'm'<<16 | 'I'<<24)
		version = 0

		offsetMagic      = 0
		offsetVersion    = 4
		offsetGeneration = 8
		offsetNSlots     = 12
		offsetUsedSlots  = 16
		offsetDummySlots = 20
		offsetXMask      = 24
		offsetKeyEnd     = 28
		offsetKeyExcess  = 32
		offsetObsolete   = 36
	)
	if len(b) < 64 {
		return io.ErrShortBuffer
	}
	if le.Uint32(b[offsetMagic:]) != magic {
		return errors.New("ndb: index: bad magic")
	}
	if le.Uint32(b[offsetVersion:]) != version {
		return errors.New("ndb: index: bad version")
	}
	i.Generation = le.Uint32(b[offsetGeneration:])
	i.NSlots = le.Uint32(b[offsetNSlots:])
	i.UsedSlots = le.Uint32(b[offsetUsedSlots:])
	i.DummySlots = le.Uint32(b[offsetDummySlots:])
	i.XMask = le.Uint32(b[offsetXMask:])
	i.KeyEnd = le.Uint32(b[offsetKeyEnd:])
	i.KeyExcess = le.Uint32(b[offsetKeyExcess:])
	// 4 bytes "obsolete"
	// 24 bytes padding
	return nil
}

// IndexPair is the package index and data offset.
type IndexPair struct {
	Package uint32
	Data    uint32
}

// Lookup returns the pair (if any) for the provided key.
func (i *Index) Lookup(s string) (pg []IndexPair, err error) {
	// NOTE(hank) This is a pretty straight forward port of the C version.
	const (
		slotSize = 8
		skip     = ^uint32(0)

		offsetKey    = 0
		offsetOffset = 4
	)
	var keyoff, x uint32
	keyh := murmur(s)
	b := make([]byte, slotSize)
Look:
	for h, hh := keyh&i.hMask, uint32(7); ; h, hh = (h+hh)&i.hMask, hh+1 {
		off := int64(8 * h)
		if _, err := i.slotSpace.ReadAt(b, off); err != nil {
			return pg, fmt.Errorf("ndb: index: failed to read slot@0x%08x: %w", off, err)
		}
		x = le.Uint32(b)
		switch {
		case x == 0:
			break Look
		case x == skip:
			continue
		}
		if keyoff == 0 {
			switch {
			case ((x ^ keyh) & i.XMask) != 0:
				continue
			case !i.equalkey(x & ^i.XMask, s):
				continue
			}
			keyoff = x
		}
		if keyoff != x {
			continue
		}
		data := le.Uint32(b[offsetOffset:])
		var ovldata uint32
		// If flagged for overflow, read the overflow segment:
		if data&0x80000000 != 0 {
			off += 4 * int64(h)
			if _, err := i.slotSpace.ReadAt(b[:4], off); err != nil {
				return pg, fmt.Errorf("ndb: index: failed to read overflow slot@0x%08x: %w", off, err)
			}
			ovldata = le.Uint32(b)
		}
		pg = append(pg, i.decodeData(data, ovldata))
	}
	return pg, nil
}

func (i *Index) equalkey(keyoff uint32, s string) bool {
	if int64(keyoff)+int64(len(s))+1 > i.keySpace.Size() {
		return false
	}
	l := len(s)
	var b []byte
	switch {
	case l < 255:
		b = make([]byte, 1+l)
	case l < 65535:
		b = make([]byte, 3+l)
	default:
		b = make([]byte, 7+l)
	}
	n, _ := i.keySpace.ReadAt(b, int64(keyoff))
	b = b[:n]
	switch {
	case l < 255:
		if b[0] != uint8(l) {
			return false
		}
		b = b[1:]
	case l < 65535:
		if b[0] != 255 || le.Uint16(b[:1]) != uint16(l) {
			return false
		}
		b = b[3:]
	default:
		if b[0] != 255 || b[1] != 255 || b[2] != 255 || le.Uint32(b[3:]) != uint32(l) {
			return false
		}
		b = b[7:]
	}
	return bytes.Equal([]byte(s), b)
}

func (i *Index) decodeData(data, ovldata uint32) (t IndexPair) {
	switch {
	case (data & 0x80000000) != 0:
		t.Data = data ^ 0x80000000
		t.Package = ovldata
	case (data & 0x40000000) != 0:
		t.Data = (data ^ 0x40000000) >> 24
		t.Package = data & 0xffffff
	default:
		t.Data = data >> 20
		t.Package = data & 0xfffff
	}
	return t
}

func (i *Index) encodeData(pkgIdx, datIdx uint32) (data, ovldata uint32) {
	switch {
	case (pkgIdx < 0x100000 && datIdx < 0x400):
		ovldata = 0
		data = pkgIdx | datIdx<<20
	case (pkgIdx < 0x1000000 && datIdx < 0x40):
		ovldata = 0
		data = pkgIdx | datIdx<<24 | 0x40000000
	default:
		ovldata = pkgIdx
		data = datIdx | 0x80000000
	}
	return data, ovldata
}

// Parse closes over the provided [io.ReaderAt] and populates the provided Index.
func (i *Index) Parse(r io.ReaderAt) error {
	const (
		indexSlotOffset   = 64
		indexKeyChunksize = 4096
	)
	b := make([]byte, indexSlotOffset)
	if _, err := r.ReadAt(b, 0); err != nil {
		return fmt.Errorf("ndb: index: unable to read bytes: %w", err)
	}
	if err := i.indexHeader.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("ndb: index: unable to unmarshal header: %w", err)
	}

	i.hMask = i.NSlots - 1
	i.slotSpace = io.NewSectionReader(r, indexSlotOffset, int64(i.NSlots)*12)
	i.keySpace = io.NewSectionReader(r, indexSlotOffset+(int64(i.NSlots)*12), int64(i.KeyEnd))

	return nil
}
