package sqlite

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

// See the reference material at
// https://rpm-software-management.github.io/rpm/manual/.

type header struct {
	tags   []byte
	data   []byte
	Infos  []entryInfo
	region tag
}

/*
The header blob is _almost_ what's described in sec. 2.4 of the File Format doc,
with some caveats:

* There's no magic header, version, and reserved block. It starts at the
  "INDEXCOUNT" entry.
*/

// These are some sizes that are useful when examining the header disk format.
const (
	entryInfoSize = 16 // sizeof(uint32)*4
	preambleSize  = 8  // sizeof(uint32)*2
)

func (h *header) Parse(ctx context.Context, b []byte) error {
	if err := h.loadArenas(ctx, b); err != nil {
		return err
	}
	if err := h.verifyRegion(ctx); err != nil {
		return err
	}
	if err := h.verifyInfo(ctx); err != nil {
		return err
	}

	return nil
}

func (h *header) ReadData(ctx context.Context, e *entryInfo) (interface{}, error) {
	switch e.Type {
	case typeBin:
		if /* is region */ false {
			return nil, errors.New("todo: handle region tags")
		}
		return h.data[e.Offset:][:e.Count], nil
	case typeI18nString, typeStringArray:
		bs := bytes.SplitN(h.data[e.Offset:], []byte{0x00}, int(e.Count+1))[:e.Count]
		s := make([]string, int(e.Count))
		for i := range bs {
			s[i] = string(bs[i])
		}
		return s, nil
	case typeString:
		// C-terminated string.
		b := h.data[e.Offset:]
		b = b[:bytes.IndexByte(b, 0x00)]
		return string(b), nil
	case typeChar, typeInt8, typeInt16, typeInt32, typeInt64:
		b := h.data[e.Offset:]
		switch e.Type {
		case typeInt64:
			r := make([]uint64, int(e.Count))
			for i := range r {
				r[i] = binary.BigEndian.Uint64(b[i*8:])
			}
			return r, nil
		case typeInt32:
			r := make([]int32, int(e.Count))
			for i := range r {
				r[i] = int32(binary.BigEndian.Uint32(b[i*4:]))
			}
			return r, nil
		case typeInt16:
			r := make([]int16, int(e.Count))
			for i := range r {
				r[i] = int16(binary.BigEndian.Uint16(b[i*2:]))
			}
			return r, nil
		case typeInt8:
			r := make([]int8, int(e.Count))
			for i := range r {
				r[i] = int8(b[i])
			}
			return r, nil
		case typeChar: // Char and Bin are different because they're offset differently.
			r := make([]byte, int(e.Count))
			copy(r, b)
			return r, nil
		}
		panic("programmer error")
	default:
	}
	return nil, fmt.Errorf("unknown type: %v", e.Type)
}

func (h *header) loadArenas(ctx context.Context, b []byte) error {
	const (
		tagsMax = 0x0000ffff
		dataMax = 0x0fffffff
		sizeMax = 256 * 1024 * 1024
	)
	tagsCt := binary.BigEndian.Uint32(b[0:])
	dataSz := binary.BigEndian.Uint32(b[4:])
	if tagsCt > tagsMax {
		return fmt.Errorf("header botch: number of tags (%d) out of range", tagsCt)
	}
	if dataSz > dataMax {
		return fmt.Errorf("header botch: data length (%d) out of range", dataSz)
	}
	tagsSz := int64(tagsCt) * entryInfoSize

	if sz := preambleSize + tagsSz + int64(dataSz); sz >= sizeMax || sz != int64(len(b)) {
		return fmt.Errorf("not enough data")
	}
	if tagsCt == 0 {
		return fmt.Errorf("no tags")
	}

	s := b[8:] // slice pointing at the start of the two arenas
	h.tags = s[:tagsSz]
	h.data = s[tagsSz : tagsSz+int64(dataSz)]
	h.Infos = make([]entryInfo, tagsCt)

	return nil
}

func (h *header) verifyRegion(ctx context.Context) error {
	region, err := h.loadTag(ctx, 0)
	if err != nil {
		return err
	}
	switch region.Tag {
	case tagHeaderSignatures:
	case tagHeaderImmutable:
	case tagHeaderImage:
	default:
		return fmt.Errorf("region tag not found")
	}
	if region.Type != typeBin || region.Count != regionTagCount {
		return fmt.Errorf("nonsense region tag: %v, count: %d", region.Type, region.Count)
	}
	if off := region.Offset + regionTagCount; off < 0 || off > int32(len(h.data)) {
		return fmt.Errorf("nonsense region offset")
	}

	var trailer entryInfo
	trailer.load(h.data[region.Offset:])
	rDataLen := region.Offset + regionTagCount
	trailer.Offset = -trailer.Offset // trailer offset is negative and special
	rIdxLen := trailer.Offset / entryInfoSize
	// Fixup copied out of librpm:
	if region.Tag == tagHeaderSignatures && trailer.Tag == tagHeaderImage {
		trailer.Tag = tagHeaderSignatures
	}
	if trailer.Tag != region.Tag || trailer.Type != typeRegionTag || trailer.Count != regionTagCount {
		return fmt.Errorf("bad region trailer: %v", trailer)
	}

	if (trailer.Offset%entryInfoSize != 0) ||
		rIdxLen > int32(len(h.tags)) ||
		rDataLen > int32(len(h.data)) {
		return fmt.Errorf("region %d size incorrect: ril %d il %d rdl %d dl %d",
			region.Tag, rIdxLen, len(h.tags), rDataLen, len(h.data))
	}
	h.region = region.Tag
	return nil
}

func (h *header) verifyInfo(ctx context.Context) error {
	lim := len(h.Infos)
	typecheck := h.region == tagHeaderImmutable || h.region == tagHeaderImage
	var prev int32

	for i := 1; i < lim; i++ {
		e, err := h.loadTag(ctx, i)
		if err != nil {
			return err
		}
		switch {
		case prev > e.Offset:
			return fmt.Errorf("botched entry: prev > offset (%d > %d)", prev, e.Offset)
		case e.Tag < tagHeaderI18nTable:
			return fmt.Errorf("botched entry: bad tag %v (%[1]d < %d)", e.Tag, tagHeaderI18nTable)
		case e.Type < typeMin || e.Type > typeMax:
			return fmt.Errorf("botched entry: bad type %v", e.Type)
		case e.Count == 0 || e.Count > uint32(len(h.data)):
			return fmt.Errorf("botched entry: bad count %d", e.Count)
		case (e.Type.alignment()-1)&e.Offset != 0:
			return fmt.Errorf("botched entry: weird alignment: type alignment %d, offset %d", e.Type.alignment(), e.Offset)
		case e.Offset < 0 || e.Offset > int32(len(h.data)):
			return fmt.Errorf("botched entry: bad offset %d", e.Offset)
		case typecheck && !checkTagType(e.Tag, e.Type):
			return fmt.Errorf("botched entry: typecheck fail: %v is not %v", e.Tag, e.Type)
		}
	}
	return nil
}

func checkTagType(key tag, typ kind) bool {
	if i, ok := tagByValue[key]; ok {
		t := tagTable[i].Type
		// Check the type. Some versions of string are typed incorrectly in a
		// compatible way.
		return t == typ || t.class() == typ.class()
	}
	// Unknown tags get a pass.
	return true
}

func (h *header) loadTag(ctx context.Context, i int) (*entryInfo, error) {
	e := &h.Infos[i]
	if e.Tag == tag(0) {
		e.load(h.tags[i*entryInfoSize:])
	}
	return e, nil
}

func headerCheckrange(sz uint32, off int32) bool { return off < 0 || uint32(off) > sz }

const regionTagCount = 16

type entryInfo struct {
	Tag    tag
	Type   kind
	Offset int32
	Count  uint32
}

func (e *entryInfo) String() string {
	return fmt.Sprintf("tag %v type %v offset %d count %d", e.Tag, e.Type, e.Offset, e.Count)
}

func (e *entryInfo) load(b []byte) {
	e.Tag = tag(int32(binary.BigEndian.Uint32(b[0:4])))
	e.Type = kind(binary.BigEndian.Uint32(b[4:8]))
	e.Offset = int32(binary.BigEndian.Uint32(b[8:12]))
	e.Count = binary.BigEndian.Uint32(b[12:16])
}
