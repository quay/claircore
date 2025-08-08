package cvss

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestMetafile(t *testing.T) {
	in, err := os.Open("testdata/feed.meta")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(in); err != nil {
		t.Fatal(err)
	}
	want := metafile{
		LastModified: time.Date(2025, time.August, 7, 3, 1, 41, 0, time.FixedZone("", -4*60*60)),
		Size:         66078439,
		ZipSize:      4924668,
		GZSize:       4924532,
		SHA256:       "D165E29D8D911F3F1E0919A5C1E8C423B14AF1C38F57847DD0A8CC9DBD027618",
	}
	var got metafile
	if err := got.Parse(&buf); err != nil {
		t.Error(err)
	}
	if !cmp.Equal(&got, &want) {
		t.Error(cmp.Diff(&got, &want))
	}
}
