package claircore

import (
	"bytes"
	"database/sql/driver"
	"fmt"
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

//go:generate stringer -type=ArchOp -linecomment

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

func (o ArchOp) Value() (driver.Value, error) {
	return o.String(), nil
}

func (o *ArchOp) Scan(i interface{}) error {
	switch v := i.(type) {
	case []byte:
		return o.UnmarshalText(v)
	case string:
		return o.UnmarshalText([]byte(v))
	case int64:
		if v >= int64(len(_ArchOp_index)-1) {
			return fmt.Errorf("unable to scan ArchOp from enum %d", v)
		}
		*o = ArchOp(v)
	default:
		return fmt.Errorf("unable to scan ArchOp from type %T", i)
	}
	return nil
}
