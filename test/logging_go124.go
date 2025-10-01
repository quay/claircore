//go:build !go1.25

package test

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func logOutput(t testing.TB) io.Writer {
	d := t.TempDir()
	n := filepath.Join(d, "output")
	t.Cleanup(func() {
		f, err := os.Open(n)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			t.Log(s.Text())
		}
		if err := s.Err(); err != nil {
			t.Error(err)
		}
	})
	w, err := os.Create(n)
	if err != nil {
		t.Fatal(err)
	}
	return w
}
