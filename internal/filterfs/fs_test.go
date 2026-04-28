package filterfs

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestCurrentDir(t *testing.T) {
	fileset := []string{
		"fs.go",
		"fs_test.go",
	}

	sys := New(os.DirFS("."))

	if err := fstest.TestFS(sys, fileset...); err != nil {
		t.Fatal(err)
	}
}

func TestSocket(t *testing.T) {
	d := t.TempDir()
	sys := New(os.DirFS(d))

	l, err := net.Listen("unix", filepath.Join(d, "socket"))
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer l.Close()
	// Passing nothing means the TestFS call should see an empty FS.
	if err := fstest.TestFS(sys); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(filepath.Join(d, "file"))
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	defer f.Close()
	// TestFS should see the new regular file that was added.
	if err := fstest.TestFS(sys, "file"); err != nil {
		t.Fatal(err)
	}
}
