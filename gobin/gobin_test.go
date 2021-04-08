package gobin

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func TestScanner(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	tmpdir := t.TempDir()

	// Build a go binary.
	outname := filepath.Join(tmpdir, "bisect")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outname, "github.com/quay/claircore/test/bisect")
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

	// Write a tarball with the binary.
	tarname := filepath.Join(tmpdir, "tar")
	tf, err := os.Create(tarname)
	if err != nil {
		t.Fatal(err)
	}
	defer tf.Close()
	tw := tar.NewWriter(tf)
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
	if err := tw.Close(); err != nil {
		t.Error(err)
	}
	t.Logf("wrote tar to: %s", tf.Name())

	// Make a fake layer with the tarball.
	l := claircore.Layer{
		Hash: claircore.MustParseDigest(`sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`),
		URI:  `file:///dev/null`,
	}
	l.SetLocal(tf.Name())

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
		case v.Name == "runtime":
			continue
		case v.Version == "(devel)":
			continue
		case v.Kind != claircore.BINARY:
		case v.PackageDB != "go:bin/bisect":
			t.Errorf("unexpected package DB: %s: %q", v.Name, v.PackageDB)
		case !verRegexp.MatchString(v.Version):
			t.Errorf("unexpected version: %s: %q", v.Name, v.Version)
		case !strings.Contains(v.Name, "/"):
			t.Errorf("unexpected module name: %q", v.Name)
		default:
			continue
		}
		t.Errorf("unexpected entry: %v", v)
	}
}

var verRegexp = regexp.MustCompile(`^v([0-9]+\.){2}[0-9]+(-[.0-9]+-[0-9a-f]+)?(\+incompatible)?$`)
