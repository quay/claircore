package filterfs

import (
	"os"
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

func TestDev(t *testing.T) {
	fileset := []string{
		"cpu",
	}

	sys := New(os.DirFS("/dev"))

	if err := fstest.TestFS(sys, fileset...); err != nil {
		t.Fatal(err)
	}
}
