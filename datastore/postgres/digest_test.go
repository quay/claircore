package postgres

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
)

func TestDigestEncode(t *testing.T) {
	var ds digestSlice = []claircore.Digest{
		claircore.MustParseDigest(`sha256:` + strings.Repeat(`a`, 64)),
		claircore.MustParseDigest(`sha256:` + strings.Repeat(`b`, 64)),
		claircore.MustParseDigest(`sha256:` + strings.Repeat(`c`, 64)),
		claircore.MustParseDigest(`sha256:` + strings.Repeat(`d`, 64)),
		claircore.MustParseDigest(`sha256:` + strings.Repeat(`e`, 64)),
		claircore.MustParseDigest(`sha256:` + strings.Repeat(`f`, 64)),
	}
	want := `{"sha256:` + strings.Repeat(`a`, 64) +
		`","sha256:` + strings.Repeat(`b`, 64) +
		`","sha256:` + strings.Repeat(`c`, 64) +
		`","sha256:` + strings.Repeat(`d`, 64) +
		`","sha256:` + strings.Repeat(`e`, 64) +
		`","sha256:` + strings.Repeat(`f`, 64) +
		`"}`
	got, err := ds.EncodeText(nil, nil)
	if err != nil {
		t.Error(err)
	}
	if got, want := got, []byte(want); !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
