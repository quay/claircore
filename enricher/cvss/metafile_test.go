package cvss

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestMetafile(t *testing.T) {
	in, err := os.Open(".testdata/feed.meta")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(in); err != nil {
		t.Fatal(err)
	}
	want := metafile{
		LastModified: time.Date(2021, time.June, 16, 3, 8, 30, 0, time.FixedZone("", -4*60*60)),
		Size:         76353511,
		ZipSize:      4070894,
		GZSize:       4070758,
		SHA256:       "708083B92E47F0B25C7DD68B89ECD9EF3F2EF91403F511AE13195A596F02E02E",
	}
	var got metafile
	if err := got.Parse(&buf); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(&got, &want) {
		t.Error(cmp.Diff(&got, &want))
	}
}
