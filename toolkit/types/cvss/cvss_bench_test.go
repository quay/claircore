package cvss

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// LoadVectorList loads a list of newline-separated CVSS vectors, omitting empty
// lines and lines starting with '#'.
//
// This is substantially the same as the "Load Fixture" functions, but only
// considers the first field and keeps the returned lines as []byte.
func loadVectorList(t testing.TB, name string) [][]byte {
	t.Helper()
	in, err := os.ReadFile(filepath.Join(`testdata`, name))
	if err != nil {
		t.Fatal(err)
	}
	vecs := bytes.Split(in, []byte{'\n'})
	vecs = slices.DeleteFunc(vecs, func(b []byte) bool {
		return len(b) == 0 || b[0] == '#'
	})
	for i, vec := range vecs {
		vecs[i] = bytes.Fields(vec)[0]
	}
	return vecs
}
