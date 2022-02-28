package types

import (
	"bytes"
	"regexp"
)

type ArchOp uint

const (
	opInvalid ArchOp = iota // invalid

	OpEquals       // equals
	OpNotEquals    // not equals
	OpPatternMatch // pattern match
)

func (o ArchOp) Cmp(a, b string) bool {
	switch {
	case b == "":
		return true
	case a == "":
		return false
	default:
	}
	switch o {
	case OpEquals:
		return a == b
	case OpNotEquals:
		return a != b
	case OpPatternMatch:
		re, err := regexp.Compile(b)
		if err != nil {
			return false
		}
		return re.MatchString(a)
	default:
	}
	return false
}

func (o ArchOp) MarshalText() (text []byte, err error) {
	return []byte(o.String()), nil
}

func (o *ArchOp) UnmarshalText(text []byte) error {
	i := bytes.Index([]byte(_ArchOp_name), text)
	if i == -1 {
		*o = ArchOp(0)
		return nil
	}
	idx := uint8(i)
	for i, off := range _ArchOp_index {
		if off == idx {
			*o = ArchOp(i)
			return nil
		}
	}
	panic("unreachable")
}
