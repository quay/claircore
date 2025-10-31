package spdx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	_ "github.com/quay/claircore/gobin"
	_ "github.com/quay/claircore/rhel"

	"github.com/quay/claircore"
)

func TestEncoder(t *testing.T) {
	e := &Encoder{
		Version: V2_3,
		Format:  JSONFormat,
		Creators: []Creator{
			{
				Creator:     "Claircore",
				CreatorType: "Tool",
			},
			{
				Creator:     "Clair",
				CreatorType: "Organization",
			},
		},
		DocumentName:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DocumentNamespace: "Test SPDX encoder namespace",
		DocumentComment:   "Test SPDX encoder comment",
	}

	ctx := context.Background()
	td := os.DirFS("testdata")
	de, err := fs.ReadDir(td, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range de {
		n := de.Name()
		if strings.HasSuffix(n, ".want.json") {
			continue
		}
		t.Run(n, func(t *testing.T) {
			f, err := td.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ext := path.Ext(n)
			base := strings.TrimSuffix(n, ext)
			wantPath := fmt.Sprintf("%s.want%s", base, ext)
			w, err := td.Open(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()

			var want map[string]any
			if err := json.NewDecoder(w).Decode(&want); err != nil {
				t.Error(err)
			}

			var buf bytes.Buffer
			var ir claircore.IndexReport
			if err := json.NewDecoder(f).Decode(&ir); err != nil {
				t.Error(err)
			}
			if err := e.Encode(ctx, &buf, &ir); err != nil {
				t.Error(err)
			}
			var got map[string]any
			if err := json.NewDecoder(&buf).Decode(&got); err != nil {
				t.Error(err)
			}

			ignoreCreatedTimestamp := cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
				return k == "created"
			})

			if !cmp.Equal(want, got, ignoreCreatedTimestamp) {
				t.Error(cmp.Diff(got, want, ignoreCreatedTimestamp))
			}
		})
	}
}
