package ndb

import "testing"

func TestMurmur(t *testing.T) {
	x := "file-magic"
	t.Logf("%s\t%08x", x, murmur(x))
}
