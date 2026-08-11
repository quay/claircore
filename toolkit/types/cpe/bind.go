package cpe

import (
	"encoding"
	"errors"
	"unsafe"
)

// BindFS returns the WFN bound as CPE 2.3 formatted string.
//
// Deprecated: use [WFN.AppendText].
//
//go:fix inline
func (w WFN) BindFS() string {
	b := make([]byte, 0, 64)
	b, err := w.AppendText(b)
	if err != nil {
		panic(err)
	}
	return string(b)
}

var (
	_ encoding.TextAppender = (*Value)(nil)
	_ encoding.TextAppender = (*WFN)(nil)
)

// AppendText implements [encoding.TextAppender].
func (w *WFN) AppendText(b []byte) ([]byte, error) {
	switch err := w.Valid(); {
	case err == nil:
	case errors.Is(err, ErrUnset):
		return []byte{}, nil
	default:
		return nil, err
	}
	b = append(b, 'c', 'p', 'e', ':', '2', '.', '3')
	for i := range NumAttr {
		// Cannot error
		b, _ = (&w.Attr[i]).AppendText(b)
	}
	return b, nil
}

// AppendText implements [encoding.TextAppender].
func (v *Value) AppendText(b []byte) ([]byte, error) {
	b = append(b, ':')
	switch v.Kind {
	case ValueUnset, ValueAny:
		return append(b, '*'), nil
	case ValueNA:
		return append(b, '-'), nil
	case ValueSet:
	default:
		panic("unreachable")
	}

	esc := false
	// SAFETY: This is all read-only.
	for _, c := range unsafe.Slice(unsafe.StringData(v.V), len(v.V)) {
		switch {
		case !esc && c == '\\':
			esc = true
			continue
		case esc && (c != '.' && c != '-' && c != '_'):
			b = append(b, '\\')
			fallthrough
		case esc:
			esc = false
		default:
		}
		b = append(b, c)
	}
	return b, nil
}
