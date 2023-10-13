package pglock

import (
	"hash/fnv"
	"unsafe"
)

// Keyify returns an int64 serialized into a []byte.
func keyify(key string) []byte {
	h := fnv.New64a()
	// This is (obviously) unsafe -- it provides mutable access to "key".
	// However, this use of unsafe follows the rules for these functions and I
	// checked the Write call to make sure it doesn't modify it.
	h.Write(unsafe.Slice(unsafe.StringData(key), len(key)))
	b := make([]byte, 0, 8)
	return h.Sum(b)
}
