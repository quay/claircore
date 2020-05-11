package cpe

import (
	"database/sql/driver"
	"errors"
	"fmt"
)

// Scan implements sql.Scanner.
func (v *Value) Scan(i interface{}) error {
	if i == nil {
		return nil
	}
	s, ok := i.(string)
	if !ok {
		return fmt.Errorf("cpe: can't scan type %T into Value", i)
	}
	v.unbindFS(nil, s)
	if err := validate(v.V); err != nil {
		return err
	}
	return nil
}

// Value implements driver.Valuer.
func (v Value) Value() (driver.Value, error) {
	if err := validate(v.V); err != nil {
		return nil, err
	}
	return v.String(), nil
}

// Scan implements sql.Scanner.
func (w *WFN) Scan(i interface{}) (err error) {
	if i == nil {
		return nil
	}
	s, ok := i.(string)
	switch {
	case !ok:
		return fmt.Errorf("cpe: can't scan type %T into WFN", i)
	case s == "":
		return nil
	}
	*w, err = Unbind(s)
	return err
}

// Value implements driver.Valuer.
func (w WFN) Value() (driver.Value, error) {
	switch err := w.Valid(); {
	case err == nil:
	case errors.Is(err, ErrUnset):
		return "", nil
	default:
		return nil, err
	}
	return w.String(), nil
}
