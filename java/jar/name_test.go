package jar

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/quay/claircore/test"
)

func TestCheckName(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)

	ms, err := fs.Glob(os.DirFS("testdata"), "*/*.jar")
	if err != nil {
		t.Error(err)
	}
	for _, n := range ms {
		i, err := checkName(ctx, n)
		switch {
		case errors.Is(err, nil):
			t.Logf("%s: %+v", n, i)
		case errors.Is(err, errUnpopulated):
			t.Log("expected:", err)
		default:
			t.Error(err)
		}
	}
}
