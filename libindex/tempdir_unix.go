//go:build unix

package libindex

import (
	"cmp"
	"os"
)

// FixTemp modifies "dir" according to the documented defaults.
//
// See [NewRemoteFetchArena].
func fixTemp(dir string) string {
	return cmp.Or(dir, os.Getenv("TMPDIR"), "/var/tmp")
}
