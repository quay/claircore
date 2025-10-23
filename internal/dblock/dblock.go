// Package dblock holds internal details of the database-based locking scheme
// that are needed in multiple places.
package dblock

import "hash/fnv"

// Keyify returns a unique int64 serialized into a []byte.
func Keyify(key string) []byte {
	h := fnv.New64a()
	h.Write([]byte(key))
	b := make([]byte, 0, 8)
	return h.Sum(b)
}
