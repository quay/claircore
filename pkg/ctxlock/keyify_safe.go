// +build safe

package ctxlock

import (
	"hash/fnv"
)

// Keyify returns an int64 serialized into a []byte.
//
// This version avoids use of "unsafe" at the cost of extra allocations.
func keyify(key string) []byte {
	h := fnv.New64a()
	h.Write([]byte(key))
	b := make([]byte, 0, 8)
	return h.Sum(b)
}
