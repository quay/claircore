package dockerfile

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
)

func TestGetLabels(t *testing.T) {
	var errPrefix = []byte("error:")
	ctx := context.Background()

	ms, err := filepath.Glob("testdata/*.txtar")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		t.Run(strings.TrimSuffix(filepath.Base(m), filepath.Ext(m)), func(t *testing.T) {
			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatalf("error parsing archive: %v", err)
			}

			var got, want map[string]string
			wantErr := bytes.HasPrefix(ar.Comment, errPrefix)
			for _, f := range ar.Files {
				switch f.Name {
				case "Dockerfile":
					got, err = GetLabels(ctx, bytes.NewReader(f.Data))
				case "Want":
					want = make(map[string]string)
					if err := json.Unmarshal(f.Data, &want); err != nil {
						t.Fatalf("unmarshaling wanted values: %v", err)
					}
				default:
					t.Logf("skipping unknown file: %s", f.Name)
				}
			}

			if wantErr {
				got := err.Error()
				want := string(bytes.TrimSpace(bytes.TrimPrefix(ar.Comment, errPrefix)))
				if got != want {
					t.Error(cmp.Diff(got, want))
				}
				return
			}
			if err != nil {
				t.Errorf("error parsing labels: %v", err)
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
			In:   "k=' v '	\v k=\"   \"",
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
