package rpmtest

import (
	"context"
	"testing"
)

func TestArchive(t *testing.T) {
	ctx := context.Background()
	a, err := OpenArchive(ctx, "testdata/archive_test.txtar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := a.Repository()
	if err != nil {
		t.Error(err)
	}
	t.Logf("repo: %q", r.ID)

	for m, err := range a.Manifests() {
		if err != nil {
			t.Error(err)
			continue
		}

		t.Logf("id: %q, %d packages", m.ImageID, len(m.RPMs))
	}

	for i, err := range a.Images() {
		if err != nil {
			t.Error(err)
			continue
		}
		t.Log(i)
	}
}
