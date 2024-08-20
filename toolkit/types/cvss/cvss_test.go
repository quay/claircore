package cvss

import (
	"bufio"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVersion(t *testing.T) {
	t.Run("V2", func(t *testing.T) {
		const want = 2
		if got := Version("AV:N/AC:L/Au:N/C:N/I:N/A:C"); got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	})
	t.Run("V3", func(t *testing.T) {
		const want = 3
		if got := Version("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"); got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
		if got := Version("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"); got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	})
	t.Run("V4", func(t *testing.T) {
		const want = 4
		if got := Version("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/SC:N/VI:L/SI:N/VA:N/SA:N"); got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	})
}

type VectorImpl[M Metric, T any] interface {
	*T
	Vector[M]
}

// Roundtrip is a test helper to ensure that all the passed vector strings
// roundtrip this package.
//
// If the incoming vector is not canonicalized, this is expected to fail; this
// package only emits canonicalized vectors.
func Roundtrip[T any, M Metric, P VectorImpl[M, T]](t *testing.T, vecs []string) {
	t.Helper()
	for _, in := range vecs {
		t.Run("", func(t *testing.T) {
			t.Helper()
			t.Log(in)
			var p P = new(T)
			err := p.UnmarshalText([]byte(in))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := p.String(), in; got != want {
				t.Error(cmp.Diff(got, want))
			}
			for i := 0; i < M(0).num(); i++ {
				m := M(i)
				t.Logf("%3v\t%#v", m, p.Get(m))
			}
		})
	}
}

// LoadRoundtripFixture loads the named file as a list of vectors.
//
// The format of the fixture is:
// - Vector string, one per line.
// - Empty lines and lines beginning with '#' are ignored.
// - Trailing words after a '#' are ignored.
func LoadRoundtripFixture(t testing.TB, file string) (vecs []string) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("opening roundtrip fixture %q: %v", file, err)
	}
	s := bufio.NewScanner(f)
	defer func() {
		if err := s.Err(); err != nil {
			t.Errorf("bufio error: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}
	}()

	for s.Scan() {
		l := s.Text()
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		if idx := strings.IndexByte(l, '#'); idx != -1 {
			l = strings.TrimSpace(l[:idx])
		}
		vecs = append(vecs, l)
	}
	return vecs
}

type ScoreTestcase struct {
	Vector string
	Score  float64
}

// Score is a test helper to ensure that the score calculation is correct for a
// vector.
func Score[T any, M Metric, P VectorImpl[M, T]](t *testing.T, tcs []ScoreTestcase) {
	t.Helper()
	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			t.Helper()
			t.Log(tc.Vector)
			x := new(T)
			var p P = x
			err := p.UnmarshalText([]byte(tc.Vector))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := p.Score(), tc.Score; got != want {
				t.Errorf("got: %4.1f, want: %4.1f", got, want)
			} else {
				t.Logf("🆗\t%4.1f %v", tc.Score, QualitativeScore[M](p))
			}
			v := reflect.ValueOf(x)
			typ := reflect.TypeOf(x)
			for i := 0; i < v.NumMethod(); i++ {
				mt := typ.Method(i)
				if mt.Type.NumOut() == 1 && mt.Type.Out(0).Kind() == reflect.Bool {
					t.Logf("%13v:\t%v",
						mt.Name,
						v.Method(i).Call([]reflect.Value{})[0])
				}
			}
		})
	}
}

// LoadScoreFixture loads the name file as a list of [ScoreTestcase].
//
// The format of the fixture is:
// - Space separated vector and decimal number, one per line.
// - Empty lines and lines beginning with '#' are ignored.
// - Fields beyond the first two are ignored.
func LoadScoreFixture(t testing.TB, file string) (tcs []ScoreTestcase) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("opening score fixture %q: %v", file, err)
	}
	s := bufio.NewScanner(f)
	defer func() {
		if err := s.Err(); err != nil {
			t.Errorf("bufio error: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}
	}()

Line:
	for s.Scan() {
		l := s.Text()
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		fs := strings.Fields(l)
		var tc ScoreTestcase
	Field:
		for i, f := range fs {
			switch i {
			case 0:
				tc.Vector = f
			case 1:
				s, err := strconv.ParseFloat(f, 64)
				if err != nil {
					t.Errorf("bad float (%v), skipping: %#q", err, l)
					continue Line
				}
				tc.Score = s
			default:
				break Field
			}
		}
		tcs = append(tcs, tc)
	}
	return tcs
}

type ErrorTestcase struct {
	Vector string
	Error  bool
}

func Error[T any, M Metric, P VectorImpl[M, T]](t *testing.T, tcs []ErrorTestcase) {
	t.Helper()
	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			t.Helper()
			t.Log(tc.Vector)
			var p P = new(T)
			err := p.UnmarshalText([]byte(tc.Vector))
			t.Logf("%v", err)
			if (err != nil) != tc.Error {
				t.Fail()
			}
		})
	}
}

// LoadErrorFixture loads the named file as a list of vectors.
//
// The format of the fixture is:
// - Vector string, one per line.
// - Empty lines and lines beginning with '#' are ignored.
// - A trailing word with "#OK" marks the line as _not_ failing.
func LoadErrorFixture(t testing.TB, file string) (tcs []ErrorTestcase) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("opening error fixture %q: %v", file, err)
	}
	s := bufio.NewScanner(f)
	defer func() {
		if err := s.Err(); err != nil {
			t.Errorf("bufio error: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("close error: %v", err)
		}
	}()

Line:
	for s.Scan() {
		l := s.Text()
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		tc := ErrorTestcase{
			Error: true,
		}
		fs := strings.Fields(l)
		for i, f := range fs {
			switch i {
			case 0:
				tc.Vector = f
			case 1:
				if f == `#OK` {
					tc.Error = false
					break
				}
				fallthrough
			default:
				t.Errorf("odd line, skipping: %#q", l)
				continue Line
			}
		}
		tcs = append(tcs, tc)
	}
	return tcs
}
