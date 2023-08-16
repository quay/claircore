package cpe

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
)

// MarshalText implements [encoding.TextMarshaler].
func (w *WFN) MarshalText() ([]byte, error) {
	switch err := w.Valid(); {
	case err == nil:
	case errors.Is(err, ErrUnset):
		return []byte{}, nil
	default:
		return nil, err
	}
	return []byte(w.BindFS()), nil
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
func (w *WFN) Scan(src interface{}) (err error) {
	switch src.(type) {
	case []byte:
		s := string(src.([]byte))
		s = strings.ToValidUTF8(s, "�")
		*w, err = Unbind(s)
	case string:
		*w, err = Unbind(src.(string))
	default:
		return fmt.Errorf("cpe: unable to Scan from type %T", src)
	}
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
