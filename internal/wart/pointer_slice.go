package wart

import (
	"iter"
	"slices"
)

// BUG(hank) There's currently a lot of API surface that that uses []*T types.
// While this minimizes the size of these slices, it increases the amount of
// pointer-chasing the GC has to do and makes it hard to think about
// allocations. In the future, we should use an [iter.Seq] with our domain types
// instead of slices. This makes the compiler work harder to be able to reduce
// allocations, but allows for the data to be handled in a streaming manner.

// AsPointer returns a sequence of pointers to the values of the inner sequence.
func AsPointer[T any](seq iter.Seq[T]) iter.Seq[*T] {
	return func(yield func(*T) bool) {
		for v := range seq { // OK because of go1.22 loop changes.
			if !yield(&v) {
				return
			}
		}
	}
}

// CollectPointer is the equivalent of "[slices.Collect]([AsPointer](seq))".
func CollectPointer[T any](seq iter.Seq[T]) []*T {
	backing := slices.Collect(seq)
	ret := make([]*T, len(backing))
	for i := range backing {
		ret[i] = &backing[i]
	}
	return ret
}
