package guestfs

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

func getSystemLibrary() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/lib/libSystem.B.dylib"
	case "linux":
		return "libc.so.6"
	default:
		panic(fmt.Errorf("GOOS %q is not supported", runtime.GOOS))
	}
}

// Libc is a table of functions to call into the C standard library.
//
// Only functions used in code are opened.
var libc struct {
	Free func(unsafe.Pointer)
}

var loadLibc = sync.OnceValue(func() error {
	handle, err := purego.Dlopen(getSystemLibrary(), purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("could not open libc: %w", err)
	}
	cfn, err := purego.Dlsym(handle, `free`)
	if err != nil {
		return fmt.Errorf("could not open libc: %w", err)
	}
	purego.RegisterFunc(&libc.Free, cfn)
	return nil
})

// Strlen is a very simple strlen implementation.
//
// # SAFETY
//
// This is allowed by Go rules, as long as the string is properly terminated. If
// it is not, this may cause a panic.
func strlen(p unsafe.Pointer) (l int) {
	//revive:disable:empty-block The side-effect of the "post" statement is used.
	for ; *(*byte)(unsafe.Add(p, l)) != 0x00; l++ {
	}
	//revive:enable:empty-block
	return l
}

// ToString returns the pointed-to C string copied into a Go string.
func toString(charstar *byte) string {
	l := strlen(unsafe.Pointer(charstar))
	src := unsafe.Slice(charstar, l)
	dst := make([]byte, l)
	copy(dst, src)
	return string(dst)
}

// RefString reinterprets the pointed-to C string as the backing memory for a Go
// string.
//
// # SAFETY
//
// The returned string is only valid as long as the pointed-to memory is valid.
func refString(charstar *byte) string {
	return unsafe.String(charstar, strlen(unsafe.Pointer(charstar)))
}

/*
// Return the number of non-NULL pointers at the pointed-to address.
func countPointers(ptrptr unsafe.Pointer) int {
	var n uintptr
	for {
		p := unsafe.Pointer(uintptr(ptrptr) + n*unsafe.Sizeof(uintptr(0)))
		if p == nil {
			break
		}
		n++
		if n > 4096 { // failsafe-ish
			panic("too many elements!")
		}
	}
	return int(n)
}

// ToStrings returns an iterator over the C memory of an array of strings. This
// function takes ownership of the memory and arranges for it to be freed when
// the iterator is exhausted.
func toStrings(ptrptr unsafe.Pointer) iter.Seq[string] {
	return func(yeild func(string) bool) {
		toFree := []unsafe.Pointer{ptrptr}
		defer func() {
			for _, p := range toFree {
				libc.Free(p)
			}
		}()

		n := uintptr(0)
		for {
			p := unsafe.Add(ptrptr, n*unsafe.Sizeof(n))
			if p == nil {
				return
			}
			toFree = append(toFree, p)

			// very simple strlen implementation:
			s := p
			for ; s != nil; s = unsafe.Add(s, 1) {
			}
			l := int(uintptr(s) - uintptr(p))

			if !yeild(unsafe.String((*byte)(p), l)) {
				return
			}
			n++
			if n > 4096 { // failsafe-ish
				panic("too many elements!")
			}
		}
	}
}
*/
