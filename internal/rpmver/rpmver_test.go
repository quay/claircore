package rpmver

import (
	"bufio"
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"iter"
	"os"
	"os/exec"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

var (
	_ fmt.Stringer             = (*Version)(nil)
	_ encoding.TextMarshaler   = (*Version)(nil)
	_ encoding.TextUnmarshaler = (*Version)(nil)
)

// Returns an iterator of line-number (1-indexed) and line.
//
// Comments and empty lines are skipped.
func lineReader(t *testing.T, name string) iter.Seq2[string, string] {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(f)
	t.Cleanup(func() {
		if err := errors.Join(s.Err(), f.Close()); err != nil {
			t.Error(err)
		}
	})

	return func(yield func(string, string) bool) {
		n := 0
		for s.Scan() {
			n++
			l := s.Text()
			switch {
			case len(l) == 0:
				continue
			case strings.HasPrefix(l, "#"):
				continue
			}
			if !yield(fmt.Sprintf("#%02d", n), l) {
				return
			}
		}
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	seq := lineReader(t, "testdata/parse")

	for n, l := range seq {
		t.Run(n, func(t *testing.T) {
			tc := strings.Fields(l)
			if len(tc) != 6 {
				t.Fatalf("malformed line: %q (need 6 space-separated fields)", l)
			}
			for i := range tc {
				tc[i] = strings.Trim(tc[i], `"'`)
			}
			in, name, epoch, version, release, architecture := tc[0], tc[1], tc[2], tc[3], tc[4], tc[5]
			// Re-implement the weird epoch behavior.
			if epoch == "" {
				epoch = "0"
			}

			want := Version{
				Version: version,
				Release: release,
				Epoch:   epoch,
			}
			if name != "" {
				want.Name = &name
			}
			if architecture != "" {
				want.Architecture = &architecture
			}

			got, err := Parse(in)
			if err != nil {
				t.Fatalf("%s: %v", in, err)
			}

			t.Logf("got: %v, want: %v", &got, &want)
			if !gocmp.Equal(got, want) {
				t.Fatalf("%s: %v", in, gocmp.Diff(got, want))
			}
		})
	}
}

func splitComparison(t *testing.T, l string) (string, cmp, string) {
	tc := strings.Fields(l)
	if len(tc) != 3 {
		t.Fatalf("malformed line: %q (need 3 space-separated fields)", l)
	}
	a, op, b := tc[0], tc[1], tc[2]

	var want cmp
	switch op {
	case "<":
		want = cmpLT
	case "==":
		want = cmpEQ
	case ">":
		want = cmpGT
	default:
		t.Fatalf(`malformed line: %q (bad "op" argument)`, l)
	}

	return a, want, b
}

func TestRpmvercmp(t *testing.T) {
	t.Parallel()
	exe, _ := exec.LookPath("rpm")
	crosscheck := exe != ""
	if crosscheck {
		t.Logf(`found %q; wlll cross-check results`, exe)
	}
	seq := lineReader(t, "testdata/rpmvercmp")

	for n, l := range seq {
		t.Run(n, func(t *testing.T) {
			a, want, b := splitComparison(t, l)
			got := cmp(rpmvercmp(a, b))
			t.Logf("%s %v %s:\tgot: % 2v, want: % 2v", a, want, b, got, want)
			if got != want {
				t.Fail()
			}

			if crosscheck {
				out, err := exec.Command(exe, `--eval`, fmt.Sprintf(`%%{lua: print(rpm.vercmp("%s", "%s"))}`, a, b)).Output()
				if err != nil {
					t.Fatalf("error exec'ing %q: %v\n%s", exe, err, string(out))
				}

				var n int
				if _, err := fmt.Sscan(string(out), &n); err != nil {
					t.Fatalf("error scanning %q: %v", string(out), err)
				}

				if got := cmp(n); got != want {
					t.Fatalf(`rpm disagrees: theirs: %v, ours: %v`, got, want)
				}
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	seq := lineReader(t, "testdata/compare")
	for n, l := range seq {
		t.Run(n, func(t *testing.T) {
			a, want, b := splitComparison(t, l)

			av, err := Parse(a)
			if err != nil {
				t.Error(err)
			}
			bv, err := Parse(b)
			if err != nil {
				t.Error(err)
			}
			if t.Failed() {
				return
			}

			got := cmp(Compare(&av, &bv))
			t.Logf("%s %v %s:\tgot: % 2v, want: % 2v", a, want, b, got, want)
			if got != want {
				t.Fail()
			}
		})
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	t.Run("UnmarshalText", func(t *testing.T) {
		const in = `fonts-filesystem-1:2.0.5-12.fc39.noarch`
		want, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		var got Version
		if err := got.UnmarshalText([]byte(in)); err != nil {
			t.Error(err)
		}

		if Compare(&got, &want) != 0 {
			t.Errorf("bad UnmarshalText: got: %#v, want: %#v", got, want)
		}
	})
	t.Run("MarshalText", func(t *testing.T) {
		in, want := `fonts-filesystem-1:2.0.5-12.fc39.noarch`, []byte(`fonts-filesystem-1:2.0.5-12.fc39.noarch`)

		v, err := Parse(in)
		if err != nil {
			t.Error(err)
		}
		got, err := v.MarshalText()
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("bad MarshalText: got: %#q, want: %#q", got, want)
		}
	})
	t.Run("IsZero", func(t *testing.T) {
		var z Version
		if !z.IsZero() {
			t.Error("expected `var z Version;` to report `IsZero() == true`")
		}
		const in = `fonts-filesystem-1:2.0.5-12.fc39.noarch`
		v, err := Parse(in)
		if err != nil {
			t.Error(err)
		}
		if v.IsZero() {
			t.Errorf("expected parsing %q to report `IsZero() == false`", in)
		}
	})
	t.Run("EVR", func(t *testing.T) {
		in, want := `fonts-filesystem-1:2.0.5-12.fc39.noarch`, `1:2.0.5-12.fc39`
		v, err := Parse(in)
		if err != nil {
			t.Error(err)
		}
		if got := v.EVR(); got != want {
			t.Errorf("bad EVR parsing: got: %q, want: %q", got, want)
		}
	})
}
