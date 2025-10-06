package gobin

import (
	"archive/tar"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestEmptyFile(t *testing.T) {
	ctx := test.Logging(t)

	mod := test.Modtime(t, "gobin_test.go") // Needs to be the name of this file.
	p := test.GenerateFixture(t, "nothing.tar", mod, func(t testing.TB, tf *os.File) {
		tmpdir := t.TempDir()
		f, err := os.Create(filepath.Join(tmpdir, "nothing"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		// Create the tar stuff
		tw := tar.NewWriter(tf)
		defer tw.Close()
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			t.Fatal(err)
		}
		hdr.Name = "./bin/nothing"
		if err := tw.WriteHeader(hdr); err != nil {
			t.Error(err)
		}
		if _, err := io.Copy(tw, f); err != nil {
			t.Error(err)
		}
	})
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	var l claircore.Layer
	if err := l.Init(ctx, &test.AnyDescription, f); err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	var s Detector
	_, err = s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
}

func TestScanner(t *testing.T) {
	ctx := test.Logging(t)

	mod := test.Modtime(t, "gobin_test.go") // Needs to be the name of this file.
	p := test.GenerateFixture(t, t.Name()+".tar", mod, func(t testing.TB, tf *os.File) {
		tmpdir := t.TempDir()

		// Build a go binary.
		outname := filepath.Join(tmpdir, "bisect")
		cmd := exec.CommandContext(ctx, "go", "build", "-o", outname, "github.com/quay/claircore/test/bisect")
		cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH=amd64") // build a Linux amd64 ELF exe, supported by clair. Unit tests may be running on another architecture
		out, err := cmd.CombinedOutput()
		if len(out) != 0 {
			t.Logf("%q", string(out))
		}
		if err != nil {
			t.Fatal(err)
		}
		inf, err := os.Open(outname)
		if err != nil {
			t.Fatal(err)
		}
		defer inf.Close()
		fi, err := inf.Stat()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote binary to: %s", inf.Name())
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			cmd := exec.CommandContext(ctx, "go", "version", "-m", inf.Name())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("error looking at toolchain reporting: %v", err)
				return
			}
			t.Logf("version information reported by toolchain:\n%s", string(out))
		})

		// Write a tarball with the binary.
		tw := tar.NewWriter(tf)
		defer tw.Close()
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			t.Fatal(err)
		}
		hdr.Name = "./bin/bisect"
		if err := tw.WriteHeader(hdr); err != nil {
			t.Error(err)
		}
		if _, err := io.Copy(tw, inf); err != nil {
			t.Error(err)
		}
	})
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	var l claircore.Layer
	if err := l.Init(ctx, &test.AnyDescription, f); err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	// Run the scanner on the fake layer.
	var s Detector
	vs, err := s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
	if len(vs) == 0 {
		t.Error("no results returned")
	}
	// Why not just have a list? It'd change on every dependency update, which
	// would be annoying.
	for _, v := range vs {
		switch {
		case v.Name == "stdlib":
			continue
		case strings.HasPrefix(v.Version, "(devel)"):
			continue
		case v.Kind != claircore.BINARY:
		case v.PackageDB != "go:bin/bisect":
			t.Errorf("unexpected package DB: %s: %q", v.Name, v.PackageDB)
		case !versionRegex.MatchString(v.Version):
			t.Errorf("unexpected version: %s: %q", v.Name, v.Version)
		case !strings.Contains(v.Name, "/"):
			t.Errorf("unexpected module name: %q", v.Name)
		default:
			continue
		}
		t.Errorf("unexpected entry: %v", v)
	}
}
