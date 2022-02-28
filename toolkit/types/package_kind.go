package types

import "bytes"

type PackageKind uint

const (
	UnknownPackage PackageKind = iota // unknown
	SourcePackage                     // source
	BinaryPackage                     // binary
)

func (k PackageKind) MarshalText() (text []byte, err error) {
	return []byte(k.String()), nil
}

func (k *PackageKind) UnmarshalText(text []byte) error {
	i := bytes.Index([]byte(_PackageKind_name), text)
	if i == -1 {
		*k = PackageKind(0)
		return nil
	}
	idx := uint8(i)
	for i, off := range _PackageKind_index {
		if off == idx {
			*k = PackageKind(i)
			return nil
		}
	}
	panic("unreachable")
}
