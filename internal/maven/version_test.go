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

func TestEquivalentModuloClassifier(t *testing.T) {
	tt := []struct {
		name  string
		short string
		long  string
		want  bool
	}{
		{
			name:  "unrecognized JDK classifier",
			short: "12.10.2",
			long:  "12.10.2.jre11",
			want:  true,
		},
		{
			name:  "unrecognized classifier on introduced boundary",
			short: "12.10.0",
			long:  "12.10.0.jre11",
			want:  true,
		},
		{
			name:  "nested unrecognized qualifier (preview-style)",
			short: "8.3.0",
			long:  "8.3.0.jre11-preview",
			want:  true,
		},
		{
			name:  "jdk classifier, not just jre",
			short: "1.0",
			long:  "1.0.jdk17",
			want:  true,
		},
		{
			name:  "classifier matching is case-insensitive",
			short: "12.10.2",
			long:  "12.10.2.JRE11",
			want:  true,
		},
		{
			// This is the key risk-reduction case: an unrecognized qualifier
			// that *isn't* shaped like a JDK-target classifier must not be
			// short-circuited, since it might carry real meaning (e.g. a
			// separately-patched, non-simultaneous variant). Only scoping to
			// "any unrecognized qualifier" (rather than specifically
			// "jre"/"jdk") would have incorrectly treated this as equivalent.
			name:  "unrecognized non-JDK qualifier must not be short-circuited",
			short: "1.2.3",
			long:  "1.2.3-hardened",
			want:  false,
		},
		{
			name:  "unrecognized non-JDK qualifier (nested) must not be short-circuited",
			short: "1.2.3",
			long:  "1.2.3.hotfix1",
			want:  false,
		},
		{
			name:  "recognized qualifier: service pack must not be short-circuited",
			short: "1.2.3",
			long:  "1.2.3-sp1",
			want:  false,
		},
		{
			name:  "recognized qualifier: release candidate must not be short-circuited",
			short: "1.2.3",
			long:  "1.2.3-rc1",
			want:  false,
		},
		{
			name:  "recognized qualifier: SNAPSHOT must not be short-circuited",
			short: "1.2.3",
			long:  "1.2.3-SNAPSHOT",
			want:  false,
		},
		{
			name:  "longer numeric version is a real distinct version, not a classifier",
			short: "1.2.3",
			long:  "1.2.3.4",
			want:  false,
		},
		{
			name:  "not a prefix at all",
			short: "12.10.1",
			long:  "12.10.2.jre11",
			want:  false,
		},
		{
			name:  "identical versions",
			short: "12.10.2",
			long:  "12.10.2",
			want:  false,
		},
		{
			name:  "short is longer than long",
			short: "12.10.2.jre11",
			long:  "12.10.2",
			want:  false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			short, err := ParseVersion(tc.short)
			if err != nil {
				t.Fatal(err)
			}
			long, err := ParseVersion(tc.long)
			if err != nil {
				t.Fatal(err)
			}
			if got := short.EquivalentModuloClassifier(long); got != tc.want {
				t.Errorf("EquivalentModuloClassifier(%q, %q) = %v, want %v", tc.short, tc.long, got, tc.want)
			}
		})
	}
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
