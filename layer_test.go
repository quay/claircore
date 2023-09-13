package claircore_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestLayer(t *testing.T) {
	ctx := context.Background()

	// Tarish is a tar-ish file.
	tarish := test.GenerateFixture(t, "tarish", time.Time{}, func(t testing.TB, f *os.File) {
		if _, err := f.Write(make([]byte, 1024)); err != nil {
			t.Fatal(err)
		}
	})
	// GoodLayer returns a layer that looks like a tar.
	//
	// This helper does not arrange for the Close method to be called.
	goodLayer := func(t *testing.T) *claircore.Layer {
		t.Helper()
		var l claircore.Layer
		desc := claircore.LayerDescription{
			Digest:    "sha256:" + strings.Repeat("00c0ffee", 8),
			MediaType: `application/vnd.oci.image.layer.v1.tar`,
		}
		f, err := os.Open(tarish)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})

		if err := l.Init(ctx, &desc, f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return &l
	}

	t.Run("Init", func(t *testing.T) {
		t.Run("Checksum", func(t *testing.T) {
			var l claircore.Layer
			desc := claircore.LayerDescription{
				Digest:    "sha256:" + strings.Repeat("00c0ffee", 9),
				MediaType: `application/octet-stream`,
			}

			err := l.Init(ctx, &desc, bytes.NewReader(nil))
			t.Logf("error: %v", err)
			if err == nil {
				t.Error("unexpected success")
			}
		})
		t.Run("MediaType", func(t *testing.T) {
			var l claircore.Layer
			desc := claircore.LayerDescription{
				Digest:    "sha256:" + strings.Repeat("00c0ffee", 8),
				MediaType: `application/octet-stream`,
			}

			err := l.Init(ctx, &desc, bytes.NewReader(nil))
			t.Logf("error: %v", err)
			if err == nil {
				t.Error("unexpected success")
			}
		})
		t.Run("Success", func(t *testing.T) {
			l := goodLayer(t)
			if err := l.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		})
		t.Run("DoubleInit", func(t *testing.T) {
			l := goodLayer(t)
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Errorf("close error: %v", err)
				}
			})
			err := l.Init(ctx, nil, nil)
			t.Logf("error: %v", err)
			if err == nil {
				t.Error("unexpected success")
			}
		})
	})
	t.Run("Close", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			l := goodLayer(t)
			if err := l.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
		})
		t.Run("DoubleClose", func(t *testing.T) {
			l := goodLayer(t)
			if err := l.Close(); err != nil {
				t.Errorf("close error: %v", err)
			}
			defer func() {
				if r := recover(); r != nil {
					switch v := r.(type) {
					case string:
						if strings.Contains(v, "Layer closed twice") {
							return
						}
						panic(r)
					default:
						panic(r)
					}
				}
			}()
			err := l.Close()
			t.Errorf("returned from second Close: %v", err)
		})
	})
	t.Run("SetLocal", func(t *testing.T) {
		var l claircore.Layer
		err := l.SetLocal("")
		t.Logf("error: %v", err)
		if err == nil {
			t.Error("unexpected success")
		}
	})
	t.Run("Fetched", func(t *testing.T) {
		t.Run("True", func(t *testing.T) {
			l := goodLayer(t)
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Errorf("close error: %v", err)
				}
			})
			f := l.Fetched()
			t.Logf("fetched: %v", f)
			if !f {
				t.Error("unexpected failure")
			}
		})
		t.Run("False", func(t *testing.T) {
			var l claircore.Layer
			f := l.Fetched()
			t.Logf("fetched: %v", f)
			if f {
				t.Error("unexpected success")
			}
		})
	})
	t.Run("FS", func(t *testing.T) {
		t.Run("Fail", func(t *testing.T) {
			var l claircore.Layer
			_, err := l.FS()
			t.Logf("error: %v", err)
			if err == nil {
				t.Error("unexpected success")
			}
		})
		t.Run("Success", func(t *testing.T) {
			l := goodLayer(t)
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Errorf("close error: %v", err)
				}
			})
			_, err := l.FS()
			t.Logf("error: %v", err)
			if err != nil {
				t.Error("unexpected error")
			}
		})
	})
	t.Run("Reader", func(t *testing.T) {
		t.Run("Fail", func(t *testing.T) {
			var l claircore.Layer
			_, err := l.Reader()
			t.Logf("error: %v", err)
			if err == nil {
				t.Error("unexpected success")
			}
		})
		t.Run("Success", func(t *testing.T) {
			l := goodLayer(t)
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Errorf("close error: %v", err)
				}
			})
			rac, err := l.Reader()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Cleanup(func() {
				if err := rac.Close(); err != nil {
					t.Errorf("reader close error: %v", err)
				}
			})
			n, err := io.Copy(io.Discard, rac)
			if n != 1024 || err != nil {
				t.Errorf("unexpected error: read %d bytes, got error: %v", n, err)
			}
		})
	})
}
