package log

import (
	"bufio"
	"context"
	"io"
	"testing"

	"github.com/rs/zerolog"
)

// TestLogger cross-wires a zerolog.Logger to print to the provided testing.TB,
// and associates it with the returned Context.
//
// It is very slow.
func TestLogger(ctx context.Context, t testing.TB) context.Context {
	r, w := io.Pipe()
	log := zerolog.New(zerolog.ConsoleWriter{Out: w, NoColor: true})
	go func() {
		defer r.Close()
		s := bufio.NewScanner(r)
		for s.Scan() && ctx.Err() == nil {
			t.Log(s.Text())
		}
	}()
	return log.WithContext(ctx)
}
