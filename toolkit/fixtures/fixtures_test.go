package fixtures

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
)

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{
			name: "simple",
			file: "testdata/manifest/simple.txtar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ar, err := txtar.ParseFile(tt.file)
			if err != nil {
				t.Fatal(err)
			}

			var input, wantJSON []byte
			for _, f := range ar.Files {
				switch f.Name {
				case "input.csv":
					input = f.Data
				case "want.json":
					wantJSON = f.Data
				}
			}
			if input == nil || wantJSON == nil {
				t.Fatal(`malformed archive: missing "input.csv" or "want.json"`)
			}

			ctx := t.Context()
			seq, err := ParseManifest(ctx, MediaTypeManifest, bytes.NewReader(input))
			if err != nil {
				t.Fatal(err)
			}

			wantBuf := bytes.NewBuffer(wantJSON)
			lineNo := 0
			for r, err := range seq {
				lineNo++
				if err != nil {
					t.Fatalf("line %d: unexpected error: %v", lineNo, err)
				}

				wantLine, wantErr := wantBuf.ReadBytes('\n')
				if wantErr != nil && len(wantLine) == 0 {
					t.Fatalf("want.json line %d: %v", lineNo, wantErr)
				}

				var want []string
				if err := json.Unmarshal(wantLine, &want); err != nil {
					t.Fatalf("want.json line %d: %v", lineNo, err)
				}

				got := []string{r.ID, r.Product, r.Status.String()}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("line %d: mismatch (-want +got):\n%s", lineNo, diff)
				}
			}

			if l := wantBuf.Len(); l != 0 {
				t.Errorf("want.json: %d unread bytes left", l)
			}
		})
	}
}
