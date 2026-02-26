package guestfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quay/claircore/test"
)

var (
	skip    error
	tryLoad sync.Once
)

func load(t testing.TB) {
	tryLoad.Do(func() {
		skip = loadLib()
		if skip != nil {
			t.Log(skip)
			return
		}
		t.Log("loaded libguestfs")
		need := []string{
			"skopeo",
			"mkfs.erofs",
			"gzip",
		}
		errs := make([]error, len(need))
		for i, exe := range need {
			_, errs[i] = exec.LookPath(exe)
		}
		skip = errors.Join(errs...)
		if skip != nil {
			t.Log(skip)
			return
		}
	})
	if skip != nil {
		t.SkipNow()
	}
}

func makeErofsFromLayer(ref string) func(testing.TB, *os.File) {
	return func(t testing.TB, out *os.File) {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
		dir := t.TempDir()
		t.Logf("using last layer in %q", ref)

		var outBuf bytes.Buffer
		var errBuf bytes.Buffer
		cmd := exec.CommandContext(t.Context(), "skopeo", "copy", "--remove-signatures", "docker://"+ref, "oci:"+dir)
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			t.Log(err)
			t.Logf("stdout:\n%s", outBuf.String())
			t.Logf("stderr:\n%s", errBuf.String())
			t.FailNow()
		}
		t.Log("fetched ref")

		type desc struct {
			MediaType string
			Digest    string
		}
		var index struct {
			Manifests []desc
		}
		f, err := os.Open(filepath.Join(dir, "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&index); err != nil {
			t.Fatal(err)
		}
		var algo, digest string
		for _, m := range index.Manifests {
			if m.MediaType == "application/vnd.oci.image.manifest.v1+json" {
				var ok bool
				algo, digest, ok = strings.Cut(m.Digest, ":")
				if ok {
					break
				}
			}
		}
		if digest == "" {
			t.Fatal("unable to find image manifest")
		}

		var manifest struct {
			Layers []desc
		}
		f, err = os.Open(filepath.Join(dir, "blobs", algo, digest))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&manifest); err != nil {
			t.Fatal(err)
		}
		slices.Reverse(manifest.Layers)
		d := manifest.Layers[0].Digest
		algo, digest, ok := strings.Cut(d, ":")
		if !ok {
			t.Fatalf("bad digest: %q", d)
		}
		t.Logf("using layer: %s:%s", algo, digest)

		layer := filepath.Join(dir, "blobs", algo, digest)

		t.Logf("writing erofs to: %s", out.Name())
		cmd = exec.CommandContext(t.Context(), "mkfs.erofs",
			"--tar=f", "--ungzip", "--sort=none", out.Name(), layer)
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			t.Log(err)
			t.Logf("stdout:\n%s", outBuf.String())
			t.Logf("stderr:\n%s", errBuf.String())
			t.FailNow()
		}
		t.Log("created erofs")
	}
}

func TestLoad(t *testing.T) {
	load(t)
	name := test.GenerateFixture(t,
		"layer.erofs",
		time.Time{},
		makeErofsFromLayer("registry.access.redhat.com/ubi9/httpd-24:latest"))

	ctx := t.Context()
	sys, err := Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer sys.Close()
	t.Log("opened erofs")

	p := `usr/sbin/httpd`
	b, err := fs.ReadFile(sys, p)
	if err != nil {
		t.Error(err)
	}
	ck := sha256.Sum256(b)
	t.Logf("%s: sha256:%x", p, ck)
	// err = fs.WalkDir(sys, "usr", func(p string, ent fs.DirEntry, err error) error {
	// 	info, err := ent.Info()
	// 	if err != nil {
	// 		t.Error(err)
	// 		return err
	// 	}
	// 	t.Log(p, fs.FormatFileInfo(info))
	// 	return nil
	// })
}
