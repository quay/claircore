//go:build unix

package libindex

import (
	"os"
)

// FixTemp modifies "dir" according to the documented defaults.
//
// See [NewRemoteFetchArena].
func fixTemp(dir string) string {
	if dir != "" {
		return dir
	}
	if d, ok := os.LookupEnv("TMPDIR"); ok && d != "" {
		return d
	}
	return "/var/tmp"
}
