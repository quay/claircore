package events

import (
	"context"
	"log/slog"
	"sync"
)

// Ctxkey is a Context key type.
//
// This is unexported so that other packages cannot construct these values.
type ctxkey int

const (
	_ ctxkey = iota

	// HandlerKey is the value used in [WithHandler]/[Logger].
	handlerKey
)

// WithHandler sets the provided [slog.Handler] to be used when calls to
// [Logger] are made with the returned [context.Context].
func WithHandler(ctx context.Context, h slog.Handler) context.Context {
	return context.WithValue(ctx, handlerKey, h)
}

// DiscardLogger returns a [slog.Logger] configured to discard all records.
var discardLogger = sync.OnceValue(func() *slog.Logger {
	return slog.New(slog.DiscardHandler)
})

// Logger returns a [slog.Logger] for recording current "request" (whatever that
// means in context) events.
//
// The returned Logger may simply ignore all events. See [WithHandler] for
// setting the backing [slog.Handler].
func Logger(ctx context.Context) *slog.Logger {
	v := ctx.Value(handlerKey)
	if v == nil {
		return discardLogger()
	}
	return slog.New(v.(slog.Handler))
}
