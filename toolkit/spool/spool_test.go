package spool

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"os"
	"testing"
)

func resetRoot(t *testing.T) {
	if root == nil {
		root.Close()
		root = nil
	}
	var err error
	root, err = os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreate(t *testing.T) {
	resetRoot(t)

	f, err := Create()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const x = `testing`
	if _, err := io.WriteString(f, x); err != nil {
		t.Error(err)
	}

	want, got := []byte(x), make([]byte, len(x))
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Error(err)
	}
	t.Logf("got: %q, want: %q", string(got), string(want))
	if !bytes.Equal(got, want) {
		t.Fail()
	}
}

func TestOpenFile(t *testing.T) {
	resetRoot(t)

	f, err := OpenFile("TestOpenFile", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const x = `testing`
	if _, err := io.WriteString(f, x); err != nil {
		t.Error(err)
	}

	want, got := []byte(x), make([]byte, len(x))
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Error(err)
	}
	t.Logf("got: %q, want: %q", string(got), string(want))
	if !bytes.Equal(got, want) {
		t.Fail()
	}
}

func TestReopen(t *testing.T) {
	resetRoot(t)

	f1, err := Create()
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()

	f2, err := Reopen(f1, os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	if _, err := io.CopyN(f1, crand.Reader, 4096); err != nil {
		t.Error(err)
	}

	off1, err := f1.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Error(err)
	}
	off2, err := f2.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Error(err)
	}
	t.Logf("f1: %d", off1)
	t.Logf("f2: %d", off2)
	if off1 != 4096 || off2 != 0 {
		t.Errorf("file descriptors are not independent")
	}

	const sz = 32
	pos := rand.Int64N(4096 - sz)
	b1, b2 := make([]byte, sz), make([]byte, sz)
	if _, err := f1.ReadAt(b1, pos); err != nil {
		t.Error(err)
	}
	if _, err := f2.ReadAt(b2, pos); err != nil {
		t.Error(err)
	}
	t.Logf("f1: %x", b1)
	t.Logf("f2: %x", b2)
	if !bytes.Equal(b1, b2) {
		t.Errorf("file descriptors have different backing")
	}
}

func TestMkdir(t *testing.T) {
	resetRoot(t)

	dir, err := Mkdir("mkdir", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	f1, err := dir.Create("file")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	if _, err := io.CopyN(f1, crand.Reader, 4096); err != nil {
		t.Error(err)
	}

	f2, err := dir.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	off1, err := f1.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Error(err)
	}
	off2, err := f2.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Error(err)
	}
	t.Logf("f1: %d", off1)
	t.Logf("f2: %d", off2)
	if off1 != 4096 || off2 != 0 {
		t.Errorf("file descriptors are not independent")
	}

	const sz = 32
	pos := rand.Int64N(4096 - sz)
	b1, b2 := make([]byte, sz), make([]byte, sz)
	if _, err := f1.ReadAt(b1, pos); err != nil {
		t.Error(err)
	}
	if _, err := f2.ReadAt(b2, pos); err != nil {
		t.Error(err)
	}
	t.Logf("f1: %x", b1)
	t.Logf("f2: %x", b2)
	if !bytes.Equal(b1, b2) {
		t.Errorf("file descriptors have different backing")
	}
}
