//go:build !windows
// +build !windows

package integration

import (
	"os"
	"syscall"
	"testing"
)

/*
Code below does some shenanigans to lock the directory that we extract to. This
has to be done because the `go test` will run package tests in parallel, so
different packages may see the extracted binaries in various states if there
was not any synchronization. We use an exclusive flock(2) as a write lock, and
obtain a shared lock as a read gate.

Without this, tests would flake on a cold cache.
*/

func lockDir(t testing.TB, dir string) (excl bool) {
	lf, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fd := int(lf.Fd())
	t.Cleanup(func() {
		if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
			t.Error(err)
		}
		if err := lf.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// Failed to lock, wait for a shared lock, then return
		t.Logf("waiting for lock on %q", dir)
		if err := syscall.Flock(fd, syscall.LOCK_SH); err != nil {
			t.Fatal(err)
		}
		return false
	}
	return true
}

func lockDirShared(t testing.TB, dir string) {
	lf, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lf.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
}
