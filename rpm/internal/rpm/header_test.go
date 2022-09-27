package rpm

import (
	"context"
	"os"
	"testing"

	"github.com/quay/zlog"
)

func TestParseHeader(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	f, err := os.Open(`testdata/package.header`)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h, err := ParseHeader(ctx, f)
	if err != nil {
		t.Error(err)
	}
	for i := range h.Infos {
		e := &h.Infos[i]
		t.Log(e.String())
		v, err := h.ReadData(ctx, e)
		if err != nil {
			t.Error(err)
		}
		switch v := v.(type) {
		case []byte:
			t.Logf("%v(%v) %T|%[3]x", e.Tag, e.Type, v)
		default:
			t.Logf("%v(%v) %T|%[3]v", e.Tag, e.Type, v)
		}
	}
}
