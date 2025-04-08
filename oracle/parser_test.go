package oracle

import (
	"context"
	"os"
	"testing"

	"github.com/quay/zlog"
)

func TestParse(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	u, err := NewUpdater(-1)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("testdata/com.oracle.elsa-2018.xml")
	if err != nil {
		t.Fatal(err)
	}

	vs, err := u.Parse(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %d vulnerabilities", len(vs))
	if got, want := len(vs), 6021; got != want {
		t.Fatalf("got: %d vulnerabilities, want: %d vulnerabilities", got, want)
	}
}
