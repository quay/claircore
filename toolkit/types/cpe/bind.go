package cpe

import (
	"encoding"
	"errors"
	"strings"
	"unsafe"
)

// BindFS returns the WFN bound as CPE 2.3 formatted string.
func (w WFN) BindFS() string {
	b := strings.Builder{}
	b.WriteString(`cpe:2.3`)
	for i := range NumAttr {
		b.WriteByte(':')
		w.Attr[i].bind(&b)
	}
	return b.String()
}

// Bind binds the value to a formatted string, writing it into the provided
// strings.Builder.
func (v *Value) bind(b *strings.Builder) (err error) {
	switch v.Kind {
	case ValueUnset, ValueAny:
		_, err = b.WriteRune('*')
	case ValueNA:
		_, err = b.WriteRune('-')
	case ValueSet:
		_, err = valueString.WriteString(b, v.V)
	}
	return err
}

// ValueString does FS character replacing.
var valueString = strings.NewReplacer(
	`\.`, `.`,
	`\-`, `-`,
	`\_`, `_`,
)

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
