package test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quay/claircore/toolkit/log"
)

var (
	// Setup installs the test log handler exactly once.
	setup = sync.OnceFunc(func() {
		slog.SetDefault(slog.New(new(handler)))
	})

	// Getwd caches [os.Getwd], since it may be called for every [slog.Record].
	getwd = sync.OnceValue(func() string {
		dir, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		return dir
	})

	// Modname caches the main module name, since it may be needed for every
	// [slog.Record].
	modname = sync.OnceValue(func() string {
		if info, ok := debug.ReadBuildInfo(); ok {
			return info.Main.Path + "/"
		}
		return ""
	})
)

type ctxKey struct{}

var logHandler ctxKey

var _ slog.Handler = (handler)(nil)

// DeferredOp is a closure used with [handler] that allows
// [slog.Handler.WithAttrs] and [slog.Handler.WithGroup] to work by deferring
// the call until the concrete [slog.Handler] implementation can be retrieved
// from a [context.Context].
//
// When a Handler isn't in the Context passed to the Enabled or Handle methods,
// the call is a no-op.
type deferredOp func(slog.Handler) slog.Handler

// Handler implements [slog.Handler] by extracting a "real" [slog.Handler] from
// the a [context.Context].
type handler []deferredOp

// Enabled implements [slog.Handler].
func (h handler) Enabled(ctx context.Context, l slog.Level) bool {
	v := ctx.Value(logHandler)
	if v == nil {
		return false // ???
	}
	lh, ok := v.(slog.Handler)
	if !ok {
		return false // ???
	}
	return lh.Enabled(ctx, l)
}

// Handle implements [slog.Handler].
func (h handler) Handle(ctx context.Context, r slog.Record) error {
	v := ctx.Value(logHandler)
	if v == nil {
		return nil // ???
	}
	lh, ok := v.(slog.Handler)
	if !ok {
		return nil // ???
	}
	for _, op := range h {
		lh = op(lh)
	}
	if v, ok := ctx.Value(log.AttrsKey).(slog.Value); ok {
		r.AddAttrs(v.Group()...)
	}
	return lh.Handle(ctx, r)
}

// WithAttrs implements [slog.Handler].
func (h handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return append(h, func(h slog.Handler) slog.Handler {
		return h.WithAttrs(attrs)
	})
}

// WithGroup implements [slog.Handler].
func (h handler) WithGroup(name string) slog.Handler {
	return append(h, func(h slog.Handler) slog.Handler {
		return h.WithGroup(name)
	})
}

// Logging returns a [context.Context] that's set up to make the default
// [slog.Logger] defer output to the provided [testing.TB] output.
func Logging(t testing.TB, parent ...context.Context) context.Context {
	setup()
	var ctx context.Context
	if len(parent) > 0 {
		ctx = parent[0]
	} else {
		// Don't use the test Context: users should pass that in if that's what
		// they want.
		ctx = context.Background()
	}
	start := time.Now()
	w := logOutput(t)
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		ReplaceAttr: func(g []string, a slog.Attr) slog.Attr {
			if g != nil {
				return a
			}
			switch a.Key {
			case "time":
				dur := time.Since(start)
				return slog.String("time", "+"+dur.String())
			case "source":
				src := a.Value.Any().(*slog.Source)
				if src.Function != "" {
					return slog.String("source", strings.TrimPrefix(src.Function, modname()))
				}
				f := src.File
				if r, err := filepath.Rel(getwd(), f); err == nil && r != "" {
					f = r
				}
				return slog.String("source", fmt.Sprintf("%s:%d", f, src.Line))
			}
			return a
		},
	})
	return context.WithValue(ctx, logHandler, h)
}
