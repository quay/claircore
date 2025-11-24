package maven

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestVersions(t *testing.T) {
	t.Run("Parse", func(t *testing.T) {
		tc := []string{
			"1.0",
			"1.0.1",
			"1-SNAPSHOT",
			"1-alpha10-SNAPSHOT",
		}
		for _, in := range tc {
			v, err := ParseVersion(in)
			t.Logf("in: %q, got: %q", in, v.c.String())
			if err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("Compare", func(t *testing.T) {
		f, err := os.Open(`testdata/compare.list`)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		lineno := 0
		for s.Scan() {
			lineno++
			l := s.Text()
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			fs := strings.Fields(l)
			tc := CompareTestcase{
				A: fs[0],
				B: fs[2],
			}
			switch fs[1] {
			case "==":
			case ">":
				tc.Op = 1
			case "<":
				tc.Op = -1
			default:
				t.Fatalf("unknown operation %q", fs[1])
			}

			t.Run(fmt.Sprintf("#%03d", lineno), tc.Run)
		}
		if err := s.Err(); err != nil {
			t.Error(err)
		}
	})
}

type CompareTestcase struct {
	A  string
	Op int
	B  string
}

func (tc CompareTestcase) Run(t *testing.T) {
	cmpOp := map[int]string{
		0:  "==",
		1:  ">",
		-1: "<",
	}
	a, err := ParseVersion(tc.A)
	if err != nil {
		t.Error(err)
	}
	b, err := ParseVersion(tc.B)
	if err != nil {
		t.Error(err)
	}
	got, want := a.Compare(b), tc.Op
	t.Log(tc.A, cmpOp[got], tc.B)
	if got != want {
		t.Logf("a: %+v", a.c)
		t.Logf("b: %+v", b.c)
		t.Errorf("wanted: %s %s %s", tc.A, cmpOp[tc.Op], tc.B)
	}
	if tc.Op == 0 {
		return
	}
	got, want = b.Compare(a), -1*tc.Op
	t.Log(tc.B, cmpOp[got], tc.A)
	if got != want {
		t.Logf("b: %+v", b.c)
		t.Logf("a: %+v", a.c)
		t.Errorf("wanted: %s %s %s", tc.B, cmpOp[want], tc.A)
	}
}
