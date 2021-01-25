package claircore

import (
	"bytes"
	"database/sql/driver"
	"fmt"
)

type Severity uint

//go:generate stringer -type=Severity

const (
	Unknown Severity = iota
	Negligible
	Low
	Medium
	High
	Critical
)

func (s *Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *Severity) UnmarshalText(b []byte) error {
	// This depends on the contents of severity_string.go.
	i := bytes.Index([]byte(_Severity_name), b)
	if i == -1 {
		return fmt.Errorf("unknown severity %q", string(b))
	}
	idx := uint8(i)
	for n, off := range _Severity_index {
		if idx == off {
			*s = Severity(n)
			return nil
		}
	}
	panic("unreachable")
}

func (s Severity) Value() (driver.Value, error) {
	return s.String(), nil
}

func (s *Severity) Scan(i interface{}) error {
	switch v := i.(type) {
	case []byte:
		return s.UnmarshalText(v)
	case string:
		return s.UnmarshalText([]byte(v))
	case int64:
		if v >= int64(len(_Severity_index)-1) {
			return fmt.Errorf("unable to scan Severity from enum %d", v)
		}
		*s = Severity(v)
	default:
		return fmt.Errorf("unable to scan Severity from type %T", i)
	}
	return nil
}
