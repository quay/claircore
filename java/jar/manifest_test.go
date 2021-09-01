package jar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/quay/zlog"
)

func TestParseManifest(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	md := os.DirFS("testdata/manifest")
	fs, err := fs.ReadDir(md, ".")
	if err != nil {
		t.Fatal(err)
	}
	// Tee the manifests for easier diagnosing.
	var buf bytes.Buffer
	for _, d := range fs {
		buf.Reset()
		f, err := md.Open(d.Name())
		if err != nil {
			t.Error(err)
			continue
		}
		tee := io.TeeReader(f, &buf)
		var i Info
		err = i.parseManifest(ctx, tee)
		f.Close()
		switch {
		case errors.Is(err, nil):
			t.Logf("%s: %+v", d.Name(), i)
		case errors.Is(err, errUnpopulated):
		default:
			t.Error(err)
		}
		t.Logf("%s: %+q", d.Name(), buf.String())
	}
}
