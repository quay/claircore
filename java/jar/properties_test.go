package jar

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/quay/zlog"
)

func TestParseProperties(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	md := os.DirFS("testdata/properties")
	fs, err := fs.ReadDir(md, ".")
	if err != nil {
		t.Fatal(err)
	}
	// Tee the properties for easier diagnosing.
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
		err = i.parseProperties(ctx, tee)
		f.Close()
		if err != nil {
			t.Error(err)
			continue
		}
		t.Logf("%s: %+v", d.Name(), i)
		t.Logf("%s: %+q", d.Name(), buf.String())
	}
}
