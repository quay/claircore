package dockerfile

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetLabels(t *testing.T) {
	ctx := context.Background()
	td := os.DirFS("testdata")
	de, err := fs.ReadDir(td, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range de {
		n := de.Name()
		if !strings.HasPrefix(n, "Dockerfile") || strings.HasSuffix(n, ".want") {
			continue
		}
		t.Run(n, func(t *testing.T) {
			f, err := td.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			w, err := td.Open(n + ".want")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()

			want := make(map[string]string)
			if err := json.NewDecoder(w).Decode(&want); err != nil {
				t.Error(err)
			}
			got, err := GetLabels(ctx, f)
			if err != nil {
				t.Error(err)
			}

			if !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

func TestSplit(t *testing.T) {
	for _, p := range []struct {
		In   string
		Want []string
	}{
		{
			In:   "",
			Want: nil,
		},
		{
			In:   "k=v",
			Want: []string{"k=v"},
		},
		{
			In:   `k=v\ v`,
			Want: []string{`k=v\ v`},
		},
		{
			In:   `k=v k=v k=v`,
			Want: []string{`k=v`, `k=v`, `k=v`},
		},
		{
			In:   `k=" v "`,
			Want: []string{`k=" v "`},
		},
		{
			In:   `k=' v '`,
			Want: []string{`k=' v '`},
		},
		{
			In:   `k=' v ' k="   "`,
			Want: []string{`k=' v '`, `k="   "`},
		},
		{
			In: "k=' v '	\v k=\"   \"",
			Want: []string{`k=' v '`, `k="   "`},
		},
		{
			In:   "k=' v ' \t\"k\"=\"   \"",
			Want: []string{`k=' v '`, `"k"="   "`},
		},
	} {
		t.Logf("input: %#q", p.In)
		got, err := splitKV('\\', p.In)
		if err != nil {
			t.Error(err)
		}
		if want := p.Want; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
