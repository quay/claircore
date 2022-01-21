package opaque

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore/libindex/driver"
)

func TestIndexer(t *testing.T) {
	var s *Indexer
	ctx := context.Background()
	l := fstest.MapFS{
		"somedir/somefile":              &fstest.MapFile{},
		"somedir/deleteme/.wh..wh..opq": &fstest.MapFile{},
	}

	got, err := s.IndexOpaque(ctx, l)
	if err != nil {
		t.Error(err)
	}
	want := []driver.LayerChange[driver.Opaque]{
		{Op: driver.OpRemove, Location: "somedir/deleteme"},
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
