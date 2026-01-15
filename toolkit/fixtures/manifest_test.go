package fixtures

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
)

func TestManifest(t *testing.T) {
	ms, _ := filepath.Glob("testdata/manifest/*.txtar")
	for _, m := range ms {
		name := strings.TrimSuffix(filepath.Base(m), ".txtar")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ar, err := txtar.ParseFile(m)
			if err != nil {
				t.Fatal(err)
			}
			var input, wantJSON *txtar.File
			for i := range ar.Files {
				f := &ar.Files[i]
				switch f.Name {
				case "input.csv":
					input = f
				case "want.json":
					wantJSON = f
				default: // Skip
				}
			}
			if input == nil || wantJSON == nil {
				t.Fatal(`malformed archive: missing "input.csv" or "want.json"`)
			}

			ctx := t.Context()
			seq, err := ParseManifest(ctx, MediaTypeManifest1, bytes.NewReader(input.Data))
			if err != nil {
				t.Fatal(err)
			}
			wantBuf := bytes.NewBuffer(wantJSON.Data)

			lineNo := 0
			for r, err := range seq {
				lineNo++
				if err != nil {
					t.Fatalf("input.csv: line %d: unexpected error: %v", lineNo, err)
				}
				wantLine, wantErr := wantBuf.ReadBytes('\n')
				if wantErr != nil && len(wantLine) == 0 {
					t.Fatalf("want.json: line %d: %v", lineNo, wantErr)
				}
				var want []string
				if err := json.Unmarshal(wantLine, &want); err != nil {
					t.Fatalf("want.json: line %d: %v", lineNo, err)
				}

				got := []string{r.ID, r.Product, r.Status.String()}
				if !cmp.Equal(got, want) {
					t.Error(cmp.Diff(got, want))
				}
			}

			if l := wantBuf.Len(); l != 0 {
				t.Errorf("want.json: %d unread bytes left", l)
			}
		})
	}
}
