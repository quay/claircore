package dockerfile

import (
	"bytes"
	"testing"
)

func FuzzLex(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		l := newLexer()
		l.Reset(bytes.NewReader(b))
		for {
			switch i := l.Next(); i.kind {
			case itemEOF:
				return
			case itemError:
				t.Fatal(i.val)
			default:
				t.Logf("%v:\t%s", i.kind, i.val)
			}
		}
	})
}

//go:generate find testdata -type f -name Dockerfile* -not -name *.want* -exec go tool file2fuzz -o testdata/fuzz/FuzzLex {} +
