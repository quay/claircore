package ringbuf

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRingbuf(t *testing.T) {
	n := []int{1, 2, 3, 4, 5, 6, 7, 8}
	t.Run("Shift", func(t *testing.T) {
		var buf Buf[int]
		buf.Init(len(n))
		for _, v := range n {
			buf.Push(v)
		}
		want := n
		t.Logf("expected read order: %v", want)
		if got := slices.Collect(buf.All()); !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Run("Pop", func(t *testing.T) {
		var buf Buf[int]
		buf.Init(len(n))
		for _, v := range n {
			buf.Push(v)
		}
		want := slices.Clone(n)
		slices.Reverse(want)
		t.Logf("expected read order: %v", want)
		if got := slices.Collect(buf.Backward()); !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Run("Wrap", func(t *testing.T) {
		var buf Buf[int]
		buf.Init(len(n))
		buf.head = ^uint32(0) - uint32(len(n)/2)
		buf.tail = buf.head
		for _, v := range n {
			buf.Push(v)
		}
		t.Logf("head: %d, tail: %d", buf.head, buf.tail)
		if buf.tail >= buf.head {
			t.Errorf("invariant failed: tail (%d) < head (%d)", buf.tail, buf.head)
		}
		want := slices.Concat(n[5:], n[:5])
		t.Logf("expected buffer state: %v", want)
		if got := buf.buf; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		want = n
		t.Logf("expected read order: %v", want)
		if got := slices.Collect(buf.All()); !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		t.Logf("head: %d, tail: %d", buf.head, buf.tail)
		if buf.tail != buf.head {
			t.Errorf("invariant failed: tail (%d) == head (%d)", buf.tail, buf.head)
		}
	})

	t.Run("Alloc", func(t *testing.T) {
		var buf Buf[rune]
		buf.Init(2)

		// Load two elements, the first one by Alloc.
		r, _ := buf.Alloc()
		if buf.Push('1') {
			t.Error(`expected "false" return after pushing 2 elements to 2-sized buffer`)
		}
		t.Logf("%-15s %q", "Alloc+Push:", buf.buf)

		const c = '0'
		// Write the element through the pointer
		*r = c
		t.Logf("%-15s %q", "pointer write:", buf.buf)

		// Remove the Alloc'd element, test that it's the value written above
		v, ok := buf.Shift()
		if !ok {
			t.Error(`expected "true" return after removing 1 element from 2-sized buffer`)
		}
		t.Logf("%-15s %q, %q", "Shift:", v, buf.buf)
		if got, want := v, c; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}

		// Write to the Alloc'd pointer again, now that the element has been
		// removed from the ring buffer.
		*r = 'f'
		t.Logf("%-15s %q, %q", "pointer write:", v, buf.buf)
		// The value returned by Shift (and Pop, although not directly tested)
		// is independent of the value in the ring buffer.
		if got, avoid := v, *r; got == avoid {
			t.Errorf("unexpected value: got: %q", got)
		}
		// The value in ring buffer *was* modified, though. This is a sharp
		// edge in the API.
		if got, want := buf.buf[0], *r; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}

		// Obtain a "fresh" pointer to the same slot with another Alloc.
		r, _ = buf.Alloc()
		t.Logf("%-15s %q, %q", "Alloc:", v, buf.buf)
		// Assert that the element was zeroed before the pointer was returned.
		if got, want := *r, '\x00'; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}

		t.Run("Wrap", func(t *testing.T) {
			const sz = 4
			var buf Buf[int]
			buf.Init(sz)

			// Push and Pop so the buffer is empty but not at the 0 position.
			for i := range sz / 2 {
				buf.Push(i)
			}
			for range sz / 2 {
				buf.Pop()
			}

			// Fill the buffer. Make sure Alloc copes with the end of the slice.
			off := sz / 2
			want := make([]int, sz)
			for i := range sz {
				v, _ := buf.Alloc()
				*v = i + off
				want[i] = i + off
			}

			got := slices.Collect(buf.All())
			t.Logf("\ngot:  %v\nwant: %v", got, want)
			if !cmp.Equal(got, want) {
				t.Fail()
			}
		})
	})

	t.Run("Sizes", func(t *testing.T) {
		var r Buf[byte]
		i := 1
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic")
			}
			if got, want := i, 31; got != want {
				t.Fatalf("expected panic: got: %d, want: %d", got, want)
			}
			sz := 1 << i
			t.Logf("bad size:  % -10d\t(%032[1]b)", sz)
		}()
		for ; i < 32; i++ {
			sz := 1 << i
			r.Init(sz)
			t.Logf("ring size: % -10d\t(%032[1]b)", sz)
		}
	})
}
