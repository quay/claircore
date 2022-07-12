package cpe

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMatch(t *testing.T) {
	// There seems to be no test vectors for the match specification.
	src := MustUnbind(`cpe:/a:Adobe::9.*::PalmOS`)
	t.Logf("srv: %+v", src)
	tgt := MustUnbind(`cpe:/a::Reader:9.3.2:-:-`)
	t.Logf("tgt: %+v", tgt)
	got := Compare(src, tgt)
	t.Logf("relations: %+v", got)
	if !got.IsDisjoint() {
		t.Error("wanted IsDisjoint() == true")
	}
	want := Relations([NumAttr]Relation{
		Equal, Subset, Superset, Superset, Superset, Disjoint, Equal, Equal, Equal, Equal, Equal,
	})
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
