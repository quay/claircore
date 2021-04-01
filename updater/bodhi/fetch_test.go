package bodhi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quay/zlog"
)

func TestUpdate(t *testing.T) {
	t.SkipNow()
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
		if err := c.Fetch(ctx, &release{Name: "F33"}, wr); err != nil {
			t.Error(err)
		}
	}()
	var u update
	dec := json.NewDecoder(rd)
	err = dec.Decode(&u)
	for i := 0; err == nil; err = dec.Decode(&u) {
		t.Logf("%d\t%s", i, u.Title)
		i++
	}
	if !errors.Is(err, io.EOF) {
		t.Error(err)
	}
}
