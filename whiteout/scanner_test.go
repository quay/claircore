package whiteout

import (
	"context"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

// files in whiteout.layer
// etc/
// etc/.wh.profile
func TestBasicWhiteout(t *testing.T) {
	t.Parallel()
	const layerfile = `testdata/whiteout.layer`
	l := claircore.Layer{
		Hash: claircore.MustParseDigest(`sha256:25fd87072f39aaebd1ee24dca825e61d9f5a0f87966c01551d31a4d8d79d37d8`),
		URI:  "file:///dev/null",
	}
	ctx := zlog.Test(context.Background(), t)

	// Set up the crafted layer
	l.SetLocal(layerfile)
	if t.Failed() {
		return
	}

	s := new(Scanner)
	files, err := s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
	if got, want := len(files), 1; got != want {
		t.Errorf("checking length, got: %d, want: %d", got, want)
	}

	for _, f := range files {
		t.Logf("got whiteout file %s", f.Path)
	}
}

// files in whiteout_advanced.layer
// a/
// a/.wh.a_file.txt
// .wh.a_root_file.txt
// .wh.b
func TestAdvancedWhiteout(t *testing.T) {
	t.Parallel()
	const layerfile = `testdata/whiteout_advanced.layer`
	l := claircore.Layer{
		Hash: claircore.MustParseDigest(`sha256:25fd87072f39aaebd1ee24dca825e61d9f5a0f87966c01551d31a4d8d79d37d8`),
		URI:  "file:///dev/null",
	}
	ctx := zlog.Test(context.Background(), t)

	// Set up the crafted layer
	l.SetLocal(layerfile)
	if t.Failed() {
		return
	}

	s := new(Scanner)
	files, err := s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
	if got, want := len(files), 3; got != want {
		t.Errorf("checking length, got: %d, want: %d", got, want)
	}

	for _, f := range files {
		t.Logf("got whiteout file %s", f.Path)
	}
}

// files in whiteout_opaque.layer
// a/
// a/.wh..wh..opq
// b/
// b/not.a.wh..wh..opq
func TestOpaqueWhiteout(t *testing.T) {
	t.Parallel()
	const layerfile = `testdata/whiteout_opaque.layer`
	l := claircore.Layer{
		Hash: claircore.MustParseDigest(`sha256:25fd87072f39aaebd1ee24dca825e61d9f5a0f87966c01551d31a4d8d79d37d8`),
		URI:  "file:///dev/null",
	}
	ctx := zlog.Test(context.Background(), t)

	// Set up the crafted layer
	l.SetLocal(layerfile)
	if t.Failed() {
		return
	}

	s := new(Scanner)
	files, err := s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
	if got, want := len(files), 1; got != want {
		t.Errorf("checking length, got: %d, want: %d", got, want)
	}

	for _, f := range files {
		t.Logf("got whiteout file %s", f.Path)
	}
}
