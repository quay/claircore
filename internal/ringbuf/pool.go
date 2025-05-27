package ringbuf

import (
	"math/bits"
	"reflect"
	"runtime"
	"sync"
)

// BUG(hank) The autosizing logic will operated on number of cores present
// rather than number of cores available if called before code that adjusts
// GOMAXPROCS (like [clair/v4/initialize/auto.CPU]). There's no way to encode
// this invariant into the program, so callers must be careful not to use
// autosizing in the "init" or "package" contexts.
//
// [clair/v4/initialize/auto.CPU]: https://pkg.go.dev/github.com/quay/clair/v4/initialize/auto#CPU

// GuessFunc guesses a good number of elements to use in a buffer.
//
// Given a number of cores available, return the nearest power of two rounding
// toward 16 with a maximum of 64 (see [ElemMax]).
func GuessFunc(sz int) int {
	usz := uint(sz)
	// If there's more than one bit, this isn't a power of two.
	if bits.OnesCount(usz) != 1 {
		// N is the exponent.
		n := bits.UintSize - bits.LeadingZeros(usz)
		// Round toward 16.
		if n > 4 {
			n--
		}
		sz = 1 << n
	}
	// Bound to a sane number.
	return max(min(sz, ElemMax), 2)
}

const (
	// ElemMax is the maximum number of elements used in a few places:
	//
	//   - [GuessFunc] will be limited to this number
	//   - [PutBuf] will discard [Buf]s with a larger backing slice capacity
	ElemMax = 64

	// TargetSize controls how much memory an individual ring buffer should use.
	//
	// [PutBuf] will discard [Buf]s with a calculated memory footprint greater
	// than this, even if it contains fewer elements than [ElemMax].
	TargetSize = 4 << 20 // about 4 MiB
)

// RingPoolMap is a map of:
//
//	reflect.Type(T) -> *pool
var ringPoolMap sync.Map

// Pool is a wrapped [sync.Pool].
//
// It includes a per-type element limit, see [PutBuf].
type pool struct {
	sync.Pool
	MaxCt int
}

// GetRingPool returns the correct [pool] for T.
func getRingPool[T any]() *pool {
	key := reflect.TypeFor[T]()
	v, ok := ringPoolMap.Load(key)
	if !ok {
		p := pool{
			Pool: sync.Pool{
				New: func() any { return new(Buf[T]) },
			},
			MaxCt: TargetSize / sizeof[T](),
		}

		v, _ = ringPoolMap.LoadOrStore(key, &p)
	}
	return v.(*pool)
}

// Sizeof returns an estimate of the size used for a given type "T".
//
// This does limited pointer chasing for the estimation.
func sizeof[T any]() (sz int) {
	ty := reflect.TypeFor[T]()
	for {
		sz += int(ty.Size())
		if ty.Kind() != reflect.Pointer {
			break
		}
		ty = ty.Elem()
	}

	return sz
}

// GetBuf returns a ring buffer for elements of type T.
//
// The returned ring buffer is sized to hold "sz" elements, guessing a size if
// <= 1. See [GuessFunc].
func GetBuf[T any](sz int) *Buf[T] {
	if sz < 2 {
		sz = GuessFunc(runtime.GOMAXPROCS(0))
	}

	b := getRingPool[T]().Get().(*Buf[T])
	if b == nil {
		b = new(Buf[T])
	}

	b.Init(sz)
	return b
}

// PutBuf stores the passed ring buffer back into the pool.
//
// If the ring buffer has been sized to hold more than [ElemMax] elements or the
// allocation size is estimated to be greater that [TargetSize], it will be
// leaked instead. This is to control the amount of memory used by the pool. The
// ring buffer's backing slice is cleared, to avoid accidentally pinning extra
// memory.
func PutBuf[T any](b *Buf[T]) {
	c := b.Limit()
	if c > ElemMax {
		// If this is getting leaked, the GC will come for anything pointed to
		// soon enough.
		return
	}
	p := getRingPool[T]()
	if c > p.MaxCt {
		// Ditto, leak.
		return
	}
	b.clear()
	p.Put(b)
}
