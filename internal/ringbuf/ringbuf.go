// Package ringbuf implements a generic ring buffer.
//
// The ring buffers implemented in this package must use power-of-two sizing.
//
// # Power Of Two Requirement
//
// The power of two requirement is to be able to use a mask instead of a modulo,
// *AND* so that the math is correct on overflow. The extra bit stolen from the
// indices allows for distinguishing between and empty and full buffer.
//
// To prove this to yourself, think of an implementation with 4-bit indexes. If
// the size is not limited to 2³−1 (= 7) but instead limited to 2⁴-1 (= 15), the
// buffer will "reset" on wrap:
//
//	 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e
//	 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
//	b⇈
//	head: 0 tail: 0
//
// Write 12 bytes:
//
//	 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e
//	 | x | x | x | x | x | x | x | x | x | x | x | x |   |   |   |
//	h↑                                              t↑
//	head: 0 tail: 12
//
// If 3 more bytes were written, it would be impossible to tell if the buffer is
// empty or full:
//
//	 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e
//	 | x | x | x | x | x | x | x | x | x | x | x | x | x | x | x |
//	b⇈
//	head: 0 tail: 0 (15 % 15)
//
// This could be tracked with a flag, but 1073741824 elements should really be
// enough for our purposes.
package ringbuf

import (
	"fmt"
	"iter"
)

// Buf is a generic ring buffer.
//
// Ring buffers are used in this package to provide caches for iterators over
// database objects. This package can tune latency (network and query overhead)
// against memory usage (reading objects into process memory) by pulling pages
// of objects into a ring buffer to supply an iterator.
//
// A Buf is not safe for concurrent use.
type Buf[T any] struct {
	// The Buf type deals with "positions" and "indices".
	//
	// A "position" is the "absolute" position in the logical stream of values.
	// The type is an unsigned integer.
	//
	// An "index" is the concrete index in the backing slice.
	// The type is an integer.
	//
	// A position can be converted to an index by the [Buf.mask] method, but an
	// index cannot be converted to a position.

	// Buf is the backing slice. The slice's length is the ring buffer's
	// capacity, and the ring buffer's length is tracked with "head" and "tail".
	buf []T
	// Head and tail are positions in the ring.
	head uint32
	tail uint32
}

// Init initializes the ring buffer to hold "sz" elements, reusing an already
// allocated backing slice if possible.
//
// "Sz" must be a positive power of two less than 2³¹−1. Init will panic if not.
//
// Adding elements to a full ring buffer or removing elements from an empty ring
// buffer will panic.
func (r *Buf[T]) Init(sz int) {
	if sz < 2 || (sz&(sz-1)) != 0 || sz > ((1<<31)-1) {
		panic(fmt.Sprintf("invalid size: %d", sz))
	}
	r.head = 0
	r.tail = 0
	if r.Limit() < sz {
		r.buf = make([]T, sz)
	} else {
		r.buf = r.buf[:sz]
	}
}

// Mask returns the appropriate index given the position.
func (r *Buf[T]) mask(i uint32) int { return int(i & uint32(len(r.buf)-1)) }

// Clear clears the entirety of the backing slice.
//
// This is useful to avoid pointers from a pooled ring buffer "pinning" memory.
func (r *Buf[T]) clear() { clear(r.buf[:cap(r.buf)]) }

// Empty reports if the ring buffer is empty.
func (r *Buf[T]) Empty() bool { return r.head == r.tail }

// Full reports if the ring buffer is full.
func (r *Buf[T]) Full() bool { return r.Len() == r.Cap() }

// Len reports the current length of the ring buffer.
func (r *Buf[T]) Len() int { return int(r.tail - r.head) }

// Cap reports the capacity of the ring buffer.
//
// This is set by [Buf.Init] and does not change unless the ring buffer is
// re-initialized.
func (r *Buf[T]) Cap() int { return len(r.buf) }

// Limit returns the capacity of the backing allocation.
//
// That is, the ring buffer can be resized up to this value without
// reallocation.
func (r *Buf[T]) Limit() int { return cap(r.buf) }

// Push appends an element to the ring buffer and reports if it is still okay to
// push elements.
func (r *Buf[T]) Push(v T) bool {
	if r.Full() {
		panic("push called on full ringbuf")
	}
	r.buf[r.mask(r.tail)] = v
	r.tail++
	return !r.Full()
}

// Alloc appends a zero element to the ring buffer, then returns a pointer to it
// and reports if it is still okay to push elements.
//
// This API has some subtle constraints:
//
//  1. The caller cannot retain this pointer without a pointer to the originating
//     ring buffer. When using the pooling functions in this package, the element
//     will be zeroed when inserted into the pool.
//  2. A reader will receive a "T", not a "*T". As such, this API cannot be used to
//     share an object to a reader. To share a type "S", the type parameter for the
//     [Buf] instance should be "*S".
//
// This API trades one allocation and one copy for one copy (to zero the new
// element) and additional restrictions on the caller that can't be expressed in
// the Go type system.
func (r *Buf[T]) Alloc() (*T, bool) {
	if r.Full() {
		panic("alloc called on full ringbuf")
	}
	i := r.mask(r.tail)
	r.tail++
	clear(r.buf[i:r.mask(r.tail)])
	return &r.buf[i], !r.Full()
}

// Shift returns the oldest element and reports if it is still okay to remove
// elements.
func (r *Buf[T]) Shift() (v T, cont bool) {
	if r.Empty() {
		panic("shift called on empty ringbuf")
	}
	v = r.buf[r.mask(r.head)]
	r.head++
	return v, !r.Empty()
}

// Pop returns the newest element and reports if it is still okay to remove
// elements.
func (r *Buf[T]) Pop() (v T, cont bool) {
	if r.Empty() {
		panic("pop called on empty ringbuf")
	}
	v = r.buf[r.mask(r.tail-1)]
	r.tail--
	return v, !r.Empty()
}

// All returns an iterator over the contents of the buffer in first in, first
// out (FIFO) order.
//
// Yielded elements are removed from the buffer, as with [Buf.Shift]. That is,
// the iterator is multiple use but mutates the state of the collection.
func (r *Buf[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		for {
			v, ok := r.Shift()
			if !yield(v) || !ok {
				return
			}
		}
	}
}

// Backward returns an iterator over the contents of the buffer in last in,
// first out (LIFO) order.
//
// Yielded elements are removed from the buffer, as with [Buf.Pop]. That is, the
// iterator is multiple use but mutates the state of the collection.
//
// This iterator is effectively draining a stack.
//
// Using this iterator when buffering a stream of values is probably not what's
// intended, as it will only reverse buffered elements. For example, given a
// stream of elements from 0 to 9 with a buffer size of 5, filling and then
// draining the buffer repeatedly will act like this:
//
//	in:  [0 1 2 3 4 5 6 7 8 9]
//	out: [4 3 2 1 0 9 8 7 6 5]
//
// The desired behavior is probably
//
//	in:  [0 1 2 3 4 5 6 7 8 9]
//	out: [9 8 7 6 5 4 3 2 1 0]
func (r *Buf[T]) Backward() iter.Seq[T] {
	return func(yield func(T) bool) {
		for {
			v, ok := r.Pop()
			if !yield(v) || !ok {
				return
			}
		}
	}
}
