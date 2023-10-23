//go:build unix && !linux

package jsonblob

import (
	"context"
	"os"
)

func diskBuf(_ context.Context) (*os.File, error) {
	f, err := os.CreateTemp(os.TempDir(), "jsonblob.*.json")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
