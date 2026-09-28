package java

import (
	"context"
	"slices"
	"testing"
	"testing/fstest"
)

func TestWalkInterestingSBOMNames(t *testing.T) {
	sys := fstest.MapFS{
		"sbom.cdx.json":    {Data: []byte("x")},
		"sbom.cdx.json.gz": {Data: []byte("x")},
		"sbom.cdx.xml":     {Data: []byte("x")},
		"sbom.cdx.xml.gz":  {Data: []byte("x")},
		"notes.txt":        {Data: []byte("x")},
	}
	seq, errf := walkInteresting(context.Background(), sys)
	var got []string
	for k, p := range seq {
		if k != fileSBoM {
			t.Errorf("%s: kind %d", p, k)
		}
		got = append(got, p)
	}
	if err := errf(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{
		"sbom.cdx.json",
		"sbom.cdx.json.gz",
		"sbom.cdx.xml",
		"sbom.cdx.xml.gz",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}
