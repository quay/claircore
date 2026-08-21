package cpe

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
)

// MarshalText implements [encoding.TextMarshaler].
func (w *WFN) MarshalText() ([]byte, error) {
	// Guess at a good initial size. Calculated via finding the mean size across
	// the CPE Name dictionary and then rounding it up.
	//
	// 	zcat testdata/dictionary.list.gz | awk '/^#/{next}/^$/{next}{ct++;sum+=length($0)}END{print sum/ct}'
	// 	55.9444 = 64
	b := make([]byte, 0, 64)
	return w.AppendText(b)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (w *WFN) UnmarshalText(b []byte) (err error) {
	if len(b) == 0 {
		return nil
	}
	*w, err = Unbind(string(b))
	return err
}

// Scan implements [sql.Scanner].
//
// Passing an empty string does not error and leaves the WFN in its current state.
func (w *WFN) Scan(src any) (err error) {
	var s string
	switch src := src.(type) {
	case []byte:
		s = strings.ToValidUTF8(string(src), "�")
	case string:
		s = src
	default:
		return fmt.Errorf("cpe: unable to Scan from type %T", src)
	}
	if s == "" {
		return nil
	}
	*w, err = Unbind(s)
	return err
}

// Value implements [driver.Valuer].
func (w *WFN) Value() (driver.Value, error) {
	switch err := w.Valid(); {
	case err == nil:
	case errors.Is(err, ErrUnset):
		return "", nil
	default:
		return nil, err
	}
	return w.BindFS(), nil
}
