package dockerfile

import (
	"bytes"
	"path/filepath"
	"testing"

	"golang.org/x/tools/txtar"
)

func FuzzLex(f *testing.F) {
	ms, err := filepath.Glob("testdata/*.txtar")
	if err != nil {
		f.Fatal(err)
	}
	for _, m := range ms {
		ar, err := txtar.ParseFile(m)
		if err != nil {
			f.Fatalf("error parsing archive: %v", err)
		}
	File:
		for _, af := range ar.Files {
			if af.Name == "Dockerfile" {
				f.Add(af.Data)
				break File
			}
		}
	}

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

// To add new files to the fuzz corpus:
//
//	go run golang.org/x/tools/cmd/file2fuzz -o testdata/fuzz/FuzzLex [FILE]
