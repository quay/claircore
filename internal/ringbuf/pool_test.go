package ringbuf

import (
	"slices"
	"testing"
)

func TestAutosizing(t *testing.T) {
	// Skip "0" as an argument, the result is machine-specific.
	tcs := []int{-1}
	tcs = append(tcs, slices.Repeat([]int{2}, 2)...)   // [ 1,  2]
	tcs = append(tcs, slices.Repeat([]int{4}, 2)...)   // [ 3,  4]
	tcs = append(tcs, slices.Repeat([]int{8}, 4)...)   // [ 5,  8]
	tcs = append(tcs, slices.Repeat([]int{16}, 23)...) // [ 9, 32)
	tcs = append(tcs, slices.Repeat([]int{32}, 32)...) // [32, 64)
	tcs = append(tcs, slices.Repeat([]int{64}, 36)...) // [64, 99]

	for in, want := range tcs {
		if in == 0 {
			continue
		}
		got := GuessFunc(in)
		t.Logf("guessFunc(%2d): got: %2d, want: %2d", in, got, want)
		if got != want {
			t.Error()
		}
	}
}

func TestSizeof(t *testing.T) {
	type BlockOf128Bytes struct {
		_00 uint64
		_01 uint64
		_02 uint64
		_03 uint64
		_04 uint64
		_05 uint64
		_06 uint64
		_07 uint64
		_08 uint64
		_09 uint64
		_10 uint64
		_11 uint64
		_12 uint64
		_13 uint64
		_14 uint64
		_15 uint64
	}
	tcs := []struct {
		Kind any
		Got  int
		Want int
	}{
		{
			Kind: uint64(0),
			Got:  sizeof[uint64](),
			Want: 8,
		},
		{
			Kind: new(uint64),
			Got:  sizeof[*uint64](),
			Want: 16,
		},
		{
			Kind: BlockOf128Bytes{},
			Got:  sizeof[BlockOf128Bytes](),
			Want: 128,
		},
	}

	for _, tc := range tcs {
		t.Logf("%T: got: %d, want: %d", tc.Kind, tc.Got, tc.Want)
		if got, want := tc.Got, tc.Want; got != want {
			t.Fail()
		}
	}
}
