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
func TestLogger(ctx context.Context, t testing.TB) (context.Context, context.CancelFunc) {
	r, w := io.Pipe()
	log := zerolog.New(zerolog.ConsoleWriter{Out: w, NoColor: true})
	ctx, done := context.WithCancel(ctx)
	// This channel makes sure the writer goroutine is dead before the
	// CancelFunc returns.
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		defer r.Close()
		s := bufio.NewScanner(r)
		for s.Scan() {
			select {
			case <-ctx.Done():
				// If done, drain the pipe.
			default:
				t.Log(s.Text())
			}
		}
	}()
	return log.WithContext(ctx), func() {
		done()
		// Make sure the writer goroutine doesn't block waiting for lines that
		// will never be written.
		w.Close()
		<-stop
	}
}
