package events

import (
	"bytes"
	"fmt"
)

// Log implements Log by writing prints to a strings.Builder.
//
// Using a Builder should prevent extra copying. The log "lines" are written
// with invalid UTF-8 sequences between them, which lets the resulting giant
// string be split easily with very little chance of mangling inputs.
type log struct {
	g     *Group
	buf   bytes.Buffer
	topic string
}

func (l *log) Printf(format string, v ...interface{}) {
	if format == "" {
		return
	}
	l.msg(fmt.Sprintf(format, v...), false)
}

func (l *log) Errorf(format string, v ...interface{}) {
	if format == "" {
		return
	}
	l.msg(fmt.Sprintf(format, v...), true)
}

func (l *log) msg(msg string, err bool) {
	if err {
		l.buf.WriteByte('\xFF')
	}
	l.buf.WriteString(msg)
	l.buf.WriteByte('\x00')
}

func (l *log) Finish() {
	b := l.buf.Bytes()
	for len(b) != 0 {
		i := bytes.IndexByte(b, '\x00')
		var m []byte
		m, b = b[:i], b[i+1:]
		err := m[0] == '\xFF'
		if err {
			m = m[1:]
		}
		l.g.event(l.topic, Event{Error: err, Message: string(m)})
	}
}

// Noop is an implementer of Log that does nothing.
type noop struct{}

func (noop) Printf(_ string, _ ...interface{}) {}
func (noop) Errorf(_ string, _ ...interface{}) {}
func (noop) Finish()                           {}
