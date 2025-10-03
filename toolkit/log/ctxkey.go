// Package log is a common spot for claircore logging.
package log

import (
	"context"
	"log/slog"
	"slices"
)

// Ctxkey is a Context key type.
//
// This is unexported so that other packages cannot construct these values.
type ctxkey int

const (
	_ ctxkey = iota

	// AttrsKey is a common value to be used with [context.Context.Value] to
	// retrieve extra logging information from [slog.Record] values produced by
	// claircore packages.
	//
	// The value returned will be a [slog.Value] of kind "Group" if present.
	AttrsKey

	// LevelKey is a common value to be used with [context.Context.Value] to
	// retrieve a per-record minimum [slog.Level] from [slog.Record] values
	// produced by claircore packages.
	LevelKey
)

// With returns a context with the arguments stored as [slog.Attr] at
// [AttrsKey].
func With(ctx context.Context, args ...any) context.Context {
	return WithAttr(ctx, argsToAttrSlice(args)...)
}

// WithAttr returns a context with the arguments stored at [AttrsKey].
func WithAttr(ctx context.Context, attrs ...slog.Attr) context.Context {
	if v, ok := ctx.Value(AttrsKey).(slog.Value); ok {
		attrs = append(v.Group(), attrs...)
	}
	seen := make(map[string]struct{}, len(attrs))
	del := func(a slog.Attr) bool {
		_, rm := seen[a.Key]
		seen[a.Key] = struct{}{}
		return rm || (a.Value.Kind() == slog.KindGroup && len(a.Value.Group()) == 0)
	}
	slices.Reverse(attrs)
	attrs = slices.DeleteFunc(attrs, del)
	slices.Reverse(attrs)

	return context.WithValue(ctx, AttrsKey, slog.GroupValue(attrs...))
}

// WithLevel returns a context with the [slog.Leveler] stored at [LevelKey].
func WithLevel(ctx context.Context, l slog.Leveler) context.Context {
	return context.WithValue(ctx, LevelKey, l)
}

// The following copied out of the [log/slog] package:

func argsToAttrSlice(args []any) []slog.Attr {
	var (
		attr  slog.Attr
		attrs []slog.Attr
	)
	for len(args) > 0 {
		attr, args = argsToAttr(args)
		attrs = append(attrs, attr)
	}
	return attrs
}

func argsToAttr(args []any) (slog.Attr, []any) {
	const badKey = `!BADKEY`
	switch x := args[0].(type) {
	case string:
		if len(args) == 1 {
			return slog.String(badKey, x), nil
		}
		return slog.Any(x, args[1]), args[2:]

	case slog.Attr:
		return x, args[1:]

	default:
		return slog.Any(badKey, x), args[1:]
	}
}
