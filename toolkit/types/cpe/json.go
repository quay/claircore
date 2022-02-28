package cpe

import "errors"

// MarshalText implements encoding.TextMarshaler.
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

// UnmarshalText implements encoding.TextUnmarshaler.
func (w *WFN) UnmarshalText(b []byte) (err error) {
	if len(b) == 0 {
		return nil
	}
	*w, err = Unbind(string(b))
	return err
}
