// +build !safe

package ctxlock

import (
	"hash/fnv"
	"reflect"
	"unsafe"
)

// Keyify returns an int64 serialized into a []byte.
func keyify(key string) []byte {
	const maxsize = 0x7fff0000
	l := len(key)
	h := fnv.New64a()
	// This is (obviously) unsafe -- it provides mutable access to "key".
	// However, it doesn't outlive this Write call, and the implementation
	// can be read to ensure it doesn't modify it.
	h.Write((*[maxsize]byte)(unsafe.Pointer((*reflect.StringHeader)(unsafe.Pointer(&key)).Data))[:l:l])
	b := make([]byte, 0, 8)
	return h.Sum(b)
}
