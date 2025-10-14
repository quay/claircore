package cvss

import (
	"bytes"
	"os"
	"testing"

	"github.com/quay/claircore/test"
)

func TestFeedIngest(t *testing.T) {
	ctx := test.Logging(t)
	in, err := os.Open("testdata/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	f, err := newItemFeed(2016, in)
	if err != nil {
		t.Error(err)
	}
	var out bytes.Buffer
	if err := f.WriteCVSS(ctx, &out); err != nil {
		t.Error(err)
	}
	b := out.Bytes()
	c := bytes.IndexByte(b, '\n')
	if c == -1 {
		t.Error("no lines?")
	}
	t.Logf("initial output:\n\t%s", string(b[:c]))
	if got, want := bytes.Count(b, []byte("\n")), 2; got != want {
		t.Errorf("got: %d lines, want: %d lines", got, want)
	}
}
