package types

import (
	"bytes"
	"fmt"
)

type Severity uint

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
