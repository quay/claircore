package log

import (
	"context"
	"log/slog"
)

// WrapHandler wraps the provided handler with an interceptor that retrieves
// [slog.Attr] values from [AttrsKey].
func WrapHandler(next slog.Handler) slog.Handler {
	return handler{next: next}
}

var _ slog.Handler = handler{}

type handler struct {
	next slog.Handler
}

// Enabled implements [slog.Handler].
func (h handler) Enabled(ctx context.Context, l slog.Level) bool {
	rec := slog.Level(1<<31 - 1)
	if l, ok := ctx.Value(LevelKey).(slog.Leveler); ok {
		rec = l.Level()
	}
	return l >= rec || h.next.Enabled(ctx, l)
}

// Handle implements [slog.Handler].
func (h handler) Handle(ctx context.Context, r slog.Record) error {
	if v, ok := ctx.Value(AttrsKey).(slog.Value); ok {
		r.AddAttrs(v.Group()...)
	}
	return h.next.Handle(ctx, r)
}

// WithAttrs implements [slog.Handler].
func (h handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.next.WithAttrs(attrs)
}

// WithGroup implements [slog.Handler].
func (h handler) WithGroup(name string) slog.Handler {
	return h.next.WithGroup(name)
}
