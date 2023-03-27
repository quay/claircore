package ndb

import (
	"os"
	"testing"

	"github.com/quay/claircore/rpm/internal/rpm"
)

func TestLoadIndex(t *testing.T) {
	idxf, err := os.Open(".testdata/Index.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idxf.Close()
	var xdb XDB
	if err := xdb.Parse(idxf); err != nil {
		t.Fatal(err)
	}
	idx, err := xdb.Index(rpm.TagName)
	if err != nil {
		t.Fatal(err)
	}
	p, err := idx.Lookup("filesystem")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+#v", p)
	if p[0].Package != 3 {
		t.Fail()
	}
}
