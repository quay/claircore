package log

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"testing/slogtest"

	"github.com/google/go-cmp/cmp"
)

func TestWrapper(t *testing.T) {
	var buf bytes.Buffer
	results := func() (out []map[string]any) {
		dec := json.NewDecoder(&buf)
		for {
			v := make(map[string]any)
			err := dec.Decode(&v)
			switch {
			case err == nil:
			case errors.Is(err, io.EOF):
				return out
			default:
				t.Error(err)
				return out
			}
			out = append(out, v)
		}
	}

	t.Run("Slogtest", func(t *testing.T) {
		h := WrapHandler(slog.NewJSONHandler(&buf, nil))
		if err := slogtest.TestHandler(h, results); err != nil {
			t.Error(err)
		}
	})

	t.Run("With", func(t *testing.T) {
		h := WrapHandler(slog.NewJSONHandler(&buf, nil))
		ctx := With(context.Background(), "c", "d")
		slog.New(h).Log(ctx, slog.LevelInfo, "test", "a", "b", "c", "z")
		want := []map[string]any{
			{
				"level": "INFO",
				"msg":   "test",
				"a":     "b",
				"c":     "d",
			},
		}
		got := results()
		delete(got[0], "time")
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})
	t.Run("WithLevel", func(t *testing.T) {
		h := WrapHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		}))
		l := slog.New(h)
		ctx := context.Background()
		l.Log(ctx, slog.LevelInfo, "test", "call", 1)
		ctx = WithLevel(ctx, slog.LevelInfo)
		l.Log(ctx, slog.LevelInfo, "test", "call", 2)

		want := []map[string]any{
			{
				"level": "INFO",
				"msg":   "test",
				"call":  2.0,
			},
		}
		got := results()
		for i := range got {
			delete(got[i], "time")
		}
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})
}
