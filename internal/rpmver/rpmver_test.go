package rpmver

import (
	"bufio"
	"encoding"
	"fmt"
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

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/parse")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)

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

		t.Run(fmt.Sprintf("#%02d", n), func(t *testing.T) {
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

func TestRpmvercmp(t *testing.T) {
	f, err := os.Open("testdata/rpmvercmp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)

	exe, _ := exec.LookPath("rpm")
	crosscheck := exe != ""
	if crosscheck {
		t.Logf(`found %q; wlll cross-check results`, exe)
	}

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
		t.Run(fmt.Sprintf("#%02d", n), func(t *testing.T) {
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

			got := cmp(rpmvercmp(a, b))
			t.Logf("%s %s %s:\tgot: % 2v, want: % 2v", a, op, b, got, want)
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
	if err := s.Err(); err != nil {
		t.Error(err)
	}
}
