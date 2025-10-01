//go:build go1.25

package test

import (
	"io"
	"testing"
)

func logOutput(t testing.TB) io.Writer {
	return t.Output()
}
