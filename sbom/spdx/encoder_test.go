package spdx

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
	"github.com/quay/claircore/purl"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/test"
)

func TestEncoder(t *testing.T) {
	ctx := test.Logging(t)
	e := &Encoder{
		Version: V2_3,
		Format:  FormatJSON,
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
	pr := purl.NewRegistry()
	pr.RegisterDetector(rhel.PackageScanner{}, rhel.GenerateRPMPURL)
	WithPURLConverter(pr)(e)

	td := os.DirFS("testdata/round-trip")
	de, err := fs.ReadDir(td, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range de {
		n := de.Name()
		if de.IsDir() || !strings.HasSuffix(n, ".ir.json") {
			continue
		}
		t.Run(n, func(t *testing.T) {
			f, err := td.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			base := strings.TrimSuffix(n, ".ir.json")
			wantPath := base + ".spdx.json"
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
