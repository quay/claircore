package spool

import (
	"context"
	"flag"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/quay/zlog"
)

var doLeaks bool

func TestMain(m *testing.M) {
	var code int
	defer func() { os.Exit(code) }()
	arenaprofile := flag.String("arenaprofile", "", "write an arena profile to `file`")
	fileprofile := flag.String("fileprofile", "", "write a file profile to `file`")
	dirprofile := flag.String("dirprofile", "", "write a dir profile to `file`")
	flag.BoolVar(&doLeaks, "leak", false, "skip some Close calls and leak some objects") // Useful for testing the profiling.
	flag.Parse()
	if *arenaprofile != "" {
		p, err := os.Create(*arenaprofile)
		if err != nil {
			panic(err)
		}
		defer p.Close()
		defer aProfile.WriteTo(p, 1)
	}
	if *dirprofile != "" {
		p, err := os.Create(*dirprofile)
		if err != nil {
			panic(err)
		}
		defer p.Close()
		defer dProfile.WriteTo(p, 1)
	}
	if *fileprofile != "" {
		p, err := os.Create(*fileprofile)
		if err != nil {
			panic(err)
		}
		defer p.Close()
		defer fProfile.WriteTo(p, 1)
	}
	code = m.Run()
}

func TestArena(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)
	a, err := NewArena(ctx, `.`, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// Intentionally leak some stuff, then use the test cleanup function to
	// check if it's properly cleaned.
	if _, err := a.NewDir(ctx, "leak"); err != nil {
		t.Error(err)
	}
	if _, err := a.NewFile(ctx, "leak"); err != nil {
		t.Error(err)
	}
	if _, err := a.Sub(ctx, "leak"); err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		ms, _ := filepath.Glob(t.Name() + `*`)
		if len(ms) != 0 {
			t.Error("arena not cleaned up")
		}
		// Forcibly remove any stragglers so that other runs aren't messed up.
		for _, p := range ms {
			if err := os.RemoveAll(p); err != nil {
				t.Log(err)
			}
		}
	})

	t.Run(`Dir`, func(t *testing.T) {
		pat := t.Name() + `*`
		d, err := a.NewDir(ctx, path.Base(t.Name()))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		got := d.Name()
		if ok, _ := filepath.Match(pat, got); !ok {
			t.Fatalf("got: %q, want: %q", got, pat)
		}
	})

	t.Run(`File`, func(t *testing.T) {
		pat := t.Name() + `*`
		f, err := a.NewFile(ctx, path.Base(t.Name()))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		got := f.Name()
		if ok, _ := filepath.Match(pat, got); !ok {
			t.Fatalf("got: %q, want: %q", got, pat)
		}

		c, err := f.Reopen()
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	})

	t.Run(`Spool`, func(t *testing.T) {
		pat := t.Name() + `*`
		f, err := a.NewSpool(ctx, path.Base(t.Name()))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		got := f.Name()
		if ok, _ := filepath.Match(pat, got); !ok {
			t.Fatalf("got: %q, want: %q", got, pat)
		}
	})

	t.Run("Reopen", func(t *testing.T) {
		f, err := a.NewSpool(ctx, "spool.")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		c, err := f.Reopen()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		t.Logf("spool: %q, clone: %q", f.Name(), c.Name())

		if _, err := io.WriteString(f, t.Name()); err != nil {
			t.Error(err)
		}
		f.Sync()
		b, err := io.ReadAll(c)
		if err != nil {
			t.Error(err)
		}
		got, want := string(b), t.Name()
		t.Logf("got: %q, want: %q", got, want)
		if got != want {
			t.Fail()
		}
	})
}

func TestDefault(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)
	a, err := NewArena(ctx, ".", t.Name())
	t.Cleanup(func() {
		// Forcibly remove the Arena, no matter what.
		os.RemoveAll(a.root)
	})
	if err != nil {
		t.Fatal(err)
	}
	SetDefault(a)
	if !doLeaks {
		defer a.Close()
	}
	f, err := NewFile(ctx, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := NewDir(ctx, "leak"); err != nil {
		t.Error(err)
	}
	if _, err := NewFile(ctx, "leak"); err != nil {
		t.Error(err)
	}
	if _, err := a.Sub(ctx, "leak"); err != nil {
		t.Error(err)
	}
}
