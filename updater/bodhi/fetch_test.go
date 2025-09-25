package bodhi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
)

func TestUpdate(t *testing.T) {
	t.Parallel() // Use the parallel annotation to run this at the end of the tests.
	integration.Skip(t)
	defer func() {
		if t.Failed() {
			t.SkipNow()
		}
	}()
	ctx := zlog.Test(context.Background(), t)
	c := client{
		Client: http.DefaultClient,
	}
	var err error
	c.Root, err = url.Parse("https://bodhi.fedoraproject.org/")
	if err != nil {
		t.Fatal(err)
	}

	ctx, done := context.WithTimeout(ctx, 120*time.Second)
	defer done()
	rd, wr := io.Pipe()
	go func() {
		defer wr.Close()
		if err := c.Fetch(ctx, &release{Name: "F35"}, wr); err != nil && !errors.Is(err, io.EOF) {
			t.Error(err)
		}
	}()
	var u update
	var buf bytes.Buffer
	dec := json.NewDecoder(io.TeeReader(rd, &buf))
	err = dec.Decode(&u)
	for i := 0; err == nil && i < 50; err = dec.Decode(&u) {
		t.Logf("%d\t%s", i, u.Title)
		i++
	}
	rd.CloseWithError(io.EOF)
	t.Logf("fetch output:\n%s", buf.String())
	if err != nil && !errors.Is(err, io.EOF) {
		t.Error(err)
	}
}
