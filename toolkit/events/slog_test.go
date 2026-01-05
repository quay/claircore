package events

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestSlog(t *testing.T) {
	t.Run("Handler", func(t *testing.T) {
		var buf bytes.Buffer
		want := slog.NewTextHandler(&buf, nil)

		ctx := WithHandler(context.Background(), want)
		h := Logger(ctx).Handler()
		got, ok := h.(*slog.TextHandler)
		if !ok {
			t.Errorf("expected a *slog.TextHandler, got: %T", h)
		}
		if got != want {
			t.Errorf("unexpected Hander: got: %p, want: %p", got, want)
		}
	})

	t.Run("Noop", func(t *testing.T) {
		want := discardLogger()
		ctx := context.Background()
		got := Logger(ctx)
		if got != want {
			t.Errorf("unexpected Logger: got: %p, want: %p", got, want)
		}
	})
}
