package dockerfile

import (
	"errors"
	"testing"

	"golang.org/x/text/transform"
)

func TestVars(t *testing.T) {
	tt := []varTestcase{
		{
			Name:   "NoTransform",
			In:     `string with no expand`,
			Out:    `string with no expand`,
			SpanSz: 21,
			SrcSz:  21,
		},
		{
			Name:   "OddEscape",
			In:     `string with \\ expand`,
			Out:    `string with \\ expand`,
			SpanSz: 21,
			SrcSz:  21,
		},
		{
			Name:    "Literal",
			In:      `string with \$literal`,
			Out:     `string with $literal`,
			SpanSz:  12,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   21,
		},
		{
			Name:    "WholeExpand",
			In:      `$X`,
			Out:     `expand`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   2,
			Setup:   setX,
		},
		{
			Name:    "WholeExpandBrace",
			In:      `${X}`,
			Out:     `expand`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   4,
			Setup:   setX,
		},
		{
			Name:    "Default",
			In:      `${X:-expand}`,
			Out:     `expand`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   12,
		},
		{
			Name:    "UnsedDefault",
			In:      `${X:-default}`,
			Out:     `expand`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   13,
			Setup:   setX,
		},
		{
			Name:    "IfSetUnset",
			In:      `${X:+expand}`,
			Out:     ``,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   12,
		},
		{
			Name:    "IfSetSet",
			In:      `${X:+expand}`,
			Out:     `expand`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   12,
			Setup:   setX,
		},
		{
			Name:    "Leading",
			In:      `::::::$X`,
			Out:     `::::::expand`,
			SpanSz:  6,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   8,
			Setup:   setX,
		},
		{
			Name:    "Trailing",
			In:      `$X::::::`,
			Out:     `expand::::::`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   8,
			Setup:   setX,
		},
		{
			Name:    "TrailingBrace",
			In:      `${X}::::::`,
			Out:     `expand::::::`,
			SpanSz:  0,
			SpanErr: transform.ErrEndOfSpan,
			SrcSz:   10,
			Setup:   setX,
		},
	}
	// TODO(hank) Need to hit the various corner error cases.
	t.Run("Span", func(t *testing.T) {
		t.Parallel()
		v := NewVars()
		for _, tc := range tt {
			t.Run(tc.Name, tc.Span(v))
		}
	})
	t.Run("Transform", func(t *testing.T) {
		t.Parallel()
		v := NewVars()
		for _, tc := range tt {
			t.Run(tc.Name, tc.Transform(v))
		}
	})
}

type varTestcase struct {
	Setup        func(testing.TB, *Vars)
	SpanErr      error
	Name         string
	In           string
	Out          string
	SpanSz       int
	SrcSz        int
	TransformErr bool
}

func (tc *varTestcase) Span(tf *Vars) func(*testing.T) {
	return func(t *testing.T) {
		if tc.Setup != nil {
			tc.Setup(t, tf)
			defer tf.Clear()
		}
		t.Logf("input: %#q", tc.In)
		got, err := tf.Span([]byte(tc.In), true)
		t.Logf("got: %v, want: %v", got, tc.SpanSz)
		if want := tc.SpanSz; got != want {
			t.Fail()
		}
		if !errors.Is(tc.SpanErr, err) {
			t.Fatalf("unexpected error: %v", err)
		} else {
			t.Logf("expected error: %v", err)
		}
	}
}

func (tc *varTestcase) Transform(tf *Vars) func(*testing.T) {
	return func(t *testing.T) {
		if tc.Setup != nil {
			tc.Setup(t, tf)
			defer tf.Clear()
		}
		t.Logf("input: %#q", tc.In)
		got, n, err := transform.String(tf, tc.In)
		t.Logf("got: %#q, want: %#q", got, tc.Out)
		if want := tc.Out; got != want {
			t.Fail()
		}
		t.Logf("got: %v, want: %v", n, tc.SrcSz)
		if got, want := n, tc.SrcSz; got != want {
			t.Fail()
		}
		if (err == nil) == tc.TransformErr {
			t.Fatalf("unexpected error: %v", err)
		} else {
			t.Logf("expected error: %v", err)
		}
	}
}

func setX(t testing.TB, v *Vars) {
	key, val := `X`, `expand`
	t.Logf("setting %s=%s", key, val)
	v.Set(key, val)
}
