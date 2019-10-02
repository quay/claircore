package log

import (
	"bufio"
	"io"
	"testing"

	"github.com/rs/zerolog"
)

// TestLogger cross-wires a zerolog.Logger to print to the provided testing.TB.
//
// It is very slow.
func TestLogger(t testing.TB) zerolog.Logger {
	r, w := io.Pipe()
	go func() {
		s := bufio.NewScanner(r)
		for s.Scan() {
			t.Log(s.Text())
		}
	}()
	return zerolog.New(zerolog.ConsoleWriter{Out: w, NoColor: true})
}
