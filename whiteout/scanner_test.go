package whiteout

import (
	"context"
	"os"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

var testScanner = &Scanner{}

// CheckCount is a helper to check the number of whiteouts returned from the
// layer in "name".
func checkCount(t testing.TB, name string, ct int) {
	t.Helper()
	ctx := zlog.Test(context.Background(), t)
	lf, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lf.Close(); err != nil {
			t.Error(err)
		}
	})
	var l claircore.Layer
	err = l.Init(ctx, &claircore.LayerDescription{
		Digest:    `sha256:25fd87072f39aaebd1ee24dca825e61d9f5a0f87966c01551d31a4d8d79d37d8`,
		URI:       "file:///dev/null",
		MediaType: test.MediaType,
		Headers:   make(map[string][]string),
	}, lf)
	if err != nil {
		t.Fatal(err)
	}

	files, err := testScanner.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
	if got, want := len(files), ct; got != want {
		t.Errorf("checking length, got: %d, want: %d", got, want)
	}
	for _, f := range files {
		t.Logf("got whiteout file %q", f.Path)
	}
}

func TestWhiteout(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		t.Parallel()
		// files in whiteout.layer
		// etc/
		// etc/.wh.profile
		checkCount(t, `testdata/whiteout.layer`, 1)
	})
	t.Run("Advanced", func(t *testing.T) {
		t.Parallel()
		// files in whiteout_advanced.layer
		// a/
		// a/.wh.a_file.txt
		// .wh.a_root_file.txt
		// .wh.b
		checkCount(t, `testdata/whiteout_advanced.layer`, 3)
	})
	t.Run("Opaque", func(t *testing.T) {
		t.Parallel()
		// files in whiteout_opaque.layer
		// a/
		// a/.wh..wh..opq
		// b/
		// b/not.a.wh..wh..opq
		checkCount(t, `testdata/whiteout_opaque.layer`, 1)
	})
}
