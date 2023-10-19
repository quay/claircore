package postgres

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"

	"github.com/google/go-cmp/cmp"
)

const someCPE = `cpe:2.3:a:projectclair:claircore:1:*:*:*:*:*:*:devel`

func TestRotate(t *testing.T) {
	type testcase[T any] struct {
		In   []T
		Want []any
	}

	t.Run("Distribution", func(t *testing.T) {
		tc := &testcase[*claircore.Distribution]{
			In: []*claircore.Distribution{nil},
			Want: []any{
				make([]*string, 1),
				make([]*string, 1),
				make([]*string, 1),
				make([]*string, 1),
				make([]*string, 1),
				make([]*string, 1),
				make([]*cpe.WFN, 1),
				make([]*string, 1),
			},
		}
		d := claircore.Distribution{
			ID:              "id",
			DID:             "did",
			Name:            "name",
			Version:         "version",
			VersionCodeName: "version_code_name",
			VersionID:       "version_id",
			Arch:            "arch",
			CPE:             cpe.MustUnbind(someCPE),
			PrettyName:      "pretty_name",
		}
		tc.In[0] = &d
		tc.Want[0].([]*string)[0] = &d.DID
		tc.Want[1].([]*string)[0] = &d.Name
		tc.Want[2].([]*string)[0] = &d.Version
		tc.Want[3].([]*string)[0] = &d.VersionCodeName
		tc.Want[4].([]*string)[0] = &d.VersionID
		tc.Want[5].([]*string)[0] = &d.Arch
		tc.Want[6].([]*cpe.WFN)[0] = &d.CPE
		tc.Want[7].([]*string)[0] = &d.PrettyName

		r := rotateArtifacts(tc.In)
		if got, want := r, tc.Want; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Run("File", func(t *testing.T) {
		f := claircore.File{
			Path: "path",
			Kind: "kind",
		}
		tc := &testcase[claircore.File]{
			In: []claircore.File{f},
			Want: []any{
				make([]*string, 1),
				make([]*claircore.FileKind, 1),
			},
		}
		tc.Want[0].([]*string)[0] = &f.Path
		tc.Want[1].([]*claircore.FileKind)[0] = &f.Kind

		r := rotateArtifacts(tc.In)
		if got, want := r, tc.Want; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	// TODO(hank) Formalize this one.
	p := []claircore.Package{
		{
			ID:             "id",
			Name:           "name",
			Version:        "version",
			Kind:           "kind",
			Source:         nil,
			PackageDB:      "packagedb",
			Filepath:       "filepath",
			RepositoryHint: "repositoryhint",
			NormalizedVersion: claircore.Version{
				Kind: "kind",
				V: [10]int32{
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
				},
			},
			Module: "module",
			Arch:   "arch",
			CPE:    cpe.MustUnbind(someCPE),
		},
	}
	t.Log(rotateArtifacts(p))

	t.Run("Repository", func(t *testing.T) {
		r := claircore.Repository{
			ID:   "id",
			Name: "name",
			Key:  "key",
			URI:  "uri",
			CPE:  cpe.MustUnbind(someCPE),
		}
		tc := &testcase[*claircore.Repository]{
			In: []*claircore.Repository{nil},
			Want: []any{
				make([]*string, 1),
				make([]*string, 1),
				make([]*string, 1),
				make([]*cpe.WFN, 1),
			},
		}
		tc.In[0] = &r
		tc.Want[0].([]*string)[0] = &r.Name
		tc.Want[1].([]*string)[0] = &r.Key
		tc.Want[2].([]*string)[0] = &r.URI
		tc.Want[3].([]*cpe.WFN)[0] = &r.CPE

		rr := rotateArtifacts(tc.In)
		if got, want := rr, tc.Want; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})
}
