package rpmdb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// Header is a parsed RPM header.
type Header struct {
	tags   *io.SectionReader
	data   *io.SectionReader
	Infos  []EntryInfo
	region Tag
}

/*
The header blob is _almost_ what's described in sec. 2.4 of the File Format doc,
with some caveats:

- There's no magic header, version, and reserved block. It starts at the
  "INDEXCOUNT" entry.
*/

// These are some sizes that are useful when examining the header disk format.
const (
	entryInfoSize = 16 // sizeof(uint32)*4
	preambleSize  = 8  // sizeof(uint32)*2
)

// ParseHeader is equivalent to
//
//	var h Header
//	err := h.Parse(ctx, r)
//	return &h, err
func ParseHeader(ctx context.Context, r io.ReaderAt) (*Header, error) {
	var h Header
	if err := h.Parse(ctx, r); err != nil {
		return nil, err
	}
	return &h, nil
}

// Parse takes a ReaderAt containing an RPM header and loads the
// entries.
//
// The ReaderAt must stay available throughout the lifetime of the Header.
func (h *Header) Parse(ctx context.Context, r io.ReaderAt) error {
	if err := h.loadArenas(ctx, r); err != nil {
		return fmt.Errorf("rpmdb: failed to parse header: %w", err)
	}
	var isBDB bool
	switch err := h.verifyRegion(ctx); {
	case errors.Is(err, nil):
	case errors.Is(err, errNoRegion):
		isBDB = true
	default:
		return fmt.Errorf("rpmdb: failed to parse header: %w", err)
	}
	if err := h.verifyInfo(ctx, isBDB); err != nil {
		return fmt.Errorf("rpmdb: failed to parse header: %w", err)
	}
	return nil
}

// ReadData returns a copy of the data indicated by the passed EntryInfo.
//
// If an error is not reported, the returned interface{} is the type indicated by the
// EntryInfo's "Type" member.
//
// NB The TypeChar, TypeInt8, TypeInt16, TypeInt32, TypeInt64, and TypeI18nString
// all return slices.
func (h *Header) ReadData(_ context.Context, e *EntryInfo) (interface{}, error) {
	// TODO(hank) Provide a generic function like `func[T any](*Header, *EntryInfo) T` to do this.
	switch e.Type {
	case TypeBin:
		if /* is region */ false {
			return nil, errors.New("todo: handle region tags")
		}
		b := make([]byte, e.count)
		if _, err := h.data.ReadAt(b, int64(e.offset)); err != nil {
			return nil, fmt.Errorf("rpmdb: header: error reading binary: %w", err)
		}
		return b, nil
	case TypeI18nString, TypeStringArray:
		sc := bufio.NewScanner(io.NewSectionReader(h.data, int64(e.offset), -1))
		sc.Split(splitCString)
		s := make([]string, int(e.count))
		for i, lim := 0, int(e.count); i < lim && sc.Scan(); i++ {
			s[i] = sc.Text()
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("rpmdb: header: error reading string array: %w", err)
		}
		return s, nil
	case TypeString:
		// C-terminated string.
		r := bufio.NewReader(io.NewSectionReader(h.data, int64(e.offset), -1))
		s, err := r.ReadString(0x00)
		if err != nil {
			return nil, fmt.Errorf("rpmdb: header: error reading string: %w", err)
		}
		// ReadString includes the delimiter, be sure to remove it.
		return s[:len(s)-1], nil
	case TypeChar, TypeInt8, TypeInt16, TypeInt32, TypeInt64:
		sr := io.NewSectionReader(h.data, int64(e.offset), -1)
		switch e.Type {
		case TypeInt64:
			r := make([]uint64, int(e.count))
			b := make([]byte, 8)
			for i := range r {
				if _, err := io.ReadFull(sr, b); err != nil {
					return nil, fmt.Errorf("rpmdb: header: error reading %T: %w", r[0], err)
				}
				r[i] = binary.BigEndian.Uint64(b)
			}
			return r, nil
		case TypeInt32:
			r := make([]int32, int(e.count))
			b := make([]byte, 4)
			for i := range r {
				if _, err := io.ReadFull(sr, b); err != nil {
					return nil, fmt.Errorf("rpmdb: header: error reading %T: %w", r[0], err)
				}
				r[i] = int32(binary.BigEndian.Uint32(b))
			}
			return r, nil
		case TypeInt16:
			r := make([]int16, int(e.count))
			b := make([]byte, 2)
			for i := range r {
				if _, err := io.ReadFull(sr, b); err != nil {
					return nil, fmt.Errorf("rpmdb: header: error reading %T: %w", r[0], err)
				}
				r[i] = int16(binary.BigEndian.Uint16(b))
			}
			return r, nil
		case TypeInt8:
			b := make([]byte, int(e.count))
			if _, err := io.ReadFull(sr, b); err != nil {
				return nil, fmt.Errorf("rpmdb: header: error reading int8: %w", err)
			}
			// Despite byte == uint8 and uint8 being convertible to int8, this is
			// the only way I can figure out to avoid an extra copy or using a
			// ByteReader, which would just have an internal buffer and be slower.
			r := unsafe.Slice((*int8)(unsafe.Pointer(&b[0])), len(b))
			return r, nil
		case TypeChar: // Char and Bin are different because they're offset differently.
			r := make([]byte, int(e.count))
			if _, err := sr.ReadAt(r, 0); err != nil {
				return nil, fmt.Errorf("rpmdb: header: error reading char: %w", err)
			}
			return r, nil
		}
		panic("unreachable")
	default:
	}
	return nil, fmt.Errorf("unknown type: %v", e.Type)
}

// SplitCString is a [bufio.SplitFunc] that splits at NUL, much like strings(1).
func splitCString(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\x00'); i >= 0 {
		return i + 1, data[0:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func (h *Header) loadArenas(_ context.Context, r io.ReaderAt) error {
	const (
		headerSz = 8
		tagsMax  = 0x0000ffff
		dataMax  = 0x0fffffff
		sizeMax  = 256 * 1024 * 1024
	)
	b := make([]byte, headerSz)
	if _, err := r.ReadAt(b, 0); err != nil {
		return fmt.Errorf("header: failed to read: %w", err)
	}
	tagsCt := binary.BigEndian.Uint32(b[0:])
	dataSz := binary.BigEndian.Uint32(b[4:])
	if tagsCt > tagsMax {
		return fmt.Errorf("header botch: number of tags (%d) out of range", tagsCt)
	}
	if dataSz > dataMax {
		return fmt.Errorf("header botch: data length (%d) out of range", dataSz)
	}
	tagsSz := int64(tagsCt) * entryInfoSize

	// Sanity check, if possible:
	var inSz int64
	switch v := r.(type) {
	case interface{ Size() int64 }:
		// Check for Size method. [ioSectionReader]s and [byte.Buffer]s have these.
		inSz = v.Size()
	case io.Seeker:
		// Seek if present.
		var err error
		inSz, err = v.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
	default:
		// Do a read for the end of the segment.
		end := preambleSize + tagsSz + int64(dataSz)
		if _, err := r.ReadAt(b, end-int64(len(b))); err != nil {
			return err
		}
		inSz = end
	}
	if sz := preambleSize + tagsSz + int64(dataSz); sz >= sizeMax || sz != inSz {
		return fmt.Errorf("not enough data")
	}
	if tagsCt == 0 {
		return fmt.Errorf("no tags")
	}

	h.tags = io.NewSectionReader(r, headerSz, tagsSz)
	h.data = io.NewSectionReader(r, headerSz+tagsSz, int64(dataSz))
	h.Infos = make([]EntryInfo, tagsCt)

	return nil
}

// ErrNoRegion is a signal back from verifyRegion that the first tag is not one
// of the expected ones.
//
// This being reported means that the region verification has been
// short-circuited.
var errNoRegion = errors.New("no initial region tag, this is probably a bdb database")

func (h *Header) verifyRegion(ctx context.Context) error {
	const regionTagCount = 16
	region, err := h.loadTag(ctx, 0)
	if err != nil {
		return err
	}
	switch region.Tag {
	case TagHeaderSignatures:
	case TagHeaderImmutable:
	case TagHeaderImage:
	default:
		return fmt.Errorf("region tag not found, got %v: %w", region.Tag, errNoRegion)
	}
	if region.Type != TypeBin || region.count != regionTagCount {
		return fmt.Errorf("nonsense region tag: %v, count: %d", region.Type, region.count)
	}
	if off := region.offset + regionTagCount; off < 0 || off > int32(h.data.Size()) {
		return fmt.Errorf("nonsense region offset")
	}

	var trailer EntryInfo
	b := make([]byte, entryInfoSize)
	if _, err := h.data.ReadAt(b, int64(region.offset)); err != nil {
		return err
	}
	if err := trailer.UnmarshalBinary(b); err != nil {
		return err
	}
	rDataLen := region.offset + regionTagCount
	trailer.offset = -trailer.offset // trailer offset is negative and special
	rIdxLen := trailer.offset / entryInfoSize
	// Fixup copied out of librpm:
	if region.Tag == TagHeaderSignatures && trailer.Tag == TagHeaderImage {
		trailer.Tag = TagHeaderSignatures
	}
	if trailer.Tag != region.Tag || trailer.Type != TypeRegionTag || trailer.count != regionTagCount {
		return fmt.Errorf("bad region trailer: %v", trailer)
	}

	if (trailer.offset%entryInfoSize != 0) ||
		int64(rIdxLen) > h.tags.Size() ||
		int64(rDataLen) > h.data.Size() {
		return fmt.Errorf("region %d size incorrect: ril %d il %d rdl %d dl %d",
			region.Tag, rIdxLen, h.tags.Size(), rDataLen, h.data.Size())
	}
	h.region = region.Tag
	return nil
}

// VerifyInfo verifies the "info" segments in the header.
//
// Experimentally, bdb database aren't always sorted the expected way. The
// passed boolean controls whether this method uses lax verification or not.
func (h *Header) verifyInfo(ctx context.Context, isBDB bool) error {
	lim := len(h.Infos)
	typecheck := h.region == TagHeaderImmutable || h.region == TagHeaderImage
	var prev int32
	start := 1
	if isBDB {
		start--
	}

	for i := start; i < lim; i++ {
		e, err := h.loadTag(ctx, i)
		if err != nil {
			return err
		}
		switch {
		case prev > e.offset:
			return fmt.Errorf("botched entry: prev > offset (%d > %d)", prev, e.offset)
		case e.Tag < TagHeaderI18nTable && !isBDB:
			return fmt.Errorf("botched entry: bad tag %v (%[1]d < %d)", e.Tag, TagHeaderI18nTable)
		case e.Type < TypeMin || e.Type > TypeMax:
			return fmt.Errorf("botched entry: bad type %v", e.Type)
		case e.count == 0 || int64(e.count) > h.data.Size():
			return fmt.Errorf("botched entry: bad count %d", e.count)
		case (e.Type.alignment()-1)&e.offset != 0:
			return fmt.Errorf("botched entry: weird alignment: type alignment %d, offset %d", e.Type.alignment(), e.offset)
		case e.offset < 0 || int64(e.offset) > h.data.Size():
			return fmt.Errorf("botched entry: bad offset %d", e.offset)
		case typecheck && !checkTagType(e.Tag, e.Type):
			return fmt.Errorf("botched entry: typecheck fail: %v is not %v", e.Tag, e.Type)
		}
	}
	return nil
}

func checkTagType(key Tag, typ Kind) bool {
	if i, ok := tagByValue[key]; ok {
		t := tagTable[i].Type
		// Check the type. Some versions of string are typed incorrectly in a
		// compatible way.
		return t == typ || t.class() == typ.class()
	}
	// Unknown tags get a pass.
	return true
}

func (h *Header) loadTag(_ context.Context, i int) (*EntryInfo, error) {
	e := &h.Infos[i]
	if e.Tag == Tag(0) {
		b := make([]byte, entryInfoSize)
		if _, err := h.tags.ReadAt(b, int64(i)*entryInfoSize); err != nil {
			return nil, fmt.Errorf("header: error reading EntryInfo: %w", err)
		}
		if err := e.UnmarshalBinary(b); err != nil {
			return nil, fmt.Errorf("header: martian EntryInfo: %w", err)
		}
	}
	return e, nil
}

// EntryInfo describes an entry for the given Tag.
type EntryInfo struct {
	Tag    Tag
	Type   Kind
	offset int32
	count  uint32
}

func (e *EntryInfo) String() string {
	return fmt.Sprintf("tag %v type %v offset %d count %d", e.Tag, e.Type, e.offset, e.count)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (e *EntryInfo) UnmarshalBinary(b []byte) error {
	if len(b) < 16 {
		return io.ErrShortBuffer
	}
	e.Tag = Tag(int32(binary.BigEndian.Uint32(b[0:4])))
	e.Type = Kind(binary.BigEndian.Uint32(b[4:8]))
	e.offset = int32(binary.BigEndian.Uint32(b[8:12]))
	e.count = binary.BigEndian.Uint32(b[12:16])
	return nil
}
