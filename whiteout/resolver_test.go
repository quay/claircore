package whiteout

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/quay/claircore"
)

func Digest(name string) claircore.Digest {
	h := sha256.New()
	io.WriteString(h, name)
	d, err := claircore.NewDigest("sha256", h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return d
}

func TestResolver(t *testing.T) {
	firstLayerHash := Digest("first layer")
	secondLayerHash := Digest("second layer")
	thirdLayerHash := Digest("third layer")
	tests := []struct {
		name                string
		ir                  *claircore.IndexReport
		layers              []*claircore.Layer
		lenPackage, lenEnvs int
	}{
		{
			name: "simple",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
					"2": {
						Name:     "something uninteresting",
						Filepath: "a/path/to/some/file/site-packages/b_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
				},
				Files: map[string]claircore.File{
					secondLayerHash.String(): {
						Path: "a/path/to/some/file/site-packages/.wh.a_package",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			lenPackage: 1,
			lenEnvs:    1,
		},
		{
			name: "simple no deletes",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
					"2": {
						Name:     "something uninteresting",
						Filepath: "a/path/to/some/file/site-packages/b_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
				},
				Files: map[string]claircore.File{
					secondLayerHash.String(): {
						Path: "a/path/to/some/different_file/site-packages/.wh.a_package",
						Kind: claircore.FileKindWhiteout,
					},
					secondLayerHash.String(): {
						Path: "a/path/to/some/different_file/.wh.site-packages",
						Kind: claircore.FileKindWhiteout,
					},
					secondLayerHash.String(): {
						Path: "a/path/to/some/.wh.different_file",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			lenPackage: 2,
			lenEnvs:    2,
		},
		{
			name: "fat finger delete",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
					"2": {
						Name:     "something uninteresting",
						Filepath: "a/path/to/some/file/site-packages/b_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
				},
				Files: map[string]claircore.File{
					secondLayerHash.String(): {
						Path: "a/path/to/some/file/.wh.site-packages",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			lenPackage: 0,
			lenEnvs:    0,
		},
		{
			name: "deleted but not a later layer",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
					"2": {
						Name:     "something uninteresting",
						Filepath: "a/path/to/some/file/site-packages/b_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
				},
				Files: map[string]claircore.File{
					firstLayerHash.String(): { // whiteout is in the same layer as packages
						Path: "a/path/to/some/file/site-packages/.wh.b_package",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			lenPackage: 2,
			lenEnvs:    2,
		},
		{
			name: "common prefix, distinct dirs test",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
					"2": {
						Name:     "something uninteresting",
						Filepath: "a/path/to/some/file/site-packages/b_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
				},
				Files: map[string]claircore.File{
					secondLayerHash.String(): {
						Path: "a/path/to/some/file/site/.wh..wh..opq",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			lenPackage: 2,
			lenEnvs:    2,
		},
		{
			name: "opaque test",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
					"2": {
						Name:     "something uninteresting",
						Filepath: "a/path/to/some/file/site-packages/b_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
				},
				Files: map[string]claircore.File{
					secondLayerHash.String(): {
						Path: "a/path/to/some/file/site-packages/.wh..wh..opq",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			lenPackage: 0,
			lenEnvs:    0,
		},
		{
			name: "added, deleted and added again",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:     "something interesting",
						Filepath: "a/path/to/some/file/site-packages/a_package/METADATA",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}, {IntroducedIn: thirdLayerHash}},
				},
				Files: map[string]claircore.File{
					secondLayerHash.String(): { // whiteout is sandwiched
						Path: "a/path/to/some/file/site-packages/.wh.a_package",
						Kind: claircore.FileKindWhiteout,
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
				{Hash: thirdLayerHash},
			},
			lenPackage: 1,
			lenEnvs:    1,
		},
	}

	r := &Resolver{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := r.Resolve(context.Background(), tc.ir, tc.layers)
			if tc.lenPackage != len(report.Packages) {
				t.Fatalf("wrong number of packages: expected: %d got: %d", tc.lenPackage, len(report.Packages))
			}
			if tc.lenEnvs != len(report.Environments) {
				t.Fatalf("wrong number of environments: expected: %d got: %d", tc.lenEnvs, len(report.Environments))
			}
		})

	}
}

func TestIsDeleted(t *testing.T) {
	type testcase struct {
		Path     string
		Whiteout string
		Deleted  bool
	}

	for _, tc := range []testcase{
		{
			Path:     "a/b",
			Whiteout: "a/.wh.b",
			Deleted:  true,
		},
		{
			Path:     "a/c",
			Whiteout: "a/.wh.b",
			Deleted:  false,
		},
		{
			Path:     "a/b/c/foo",
			Whiteout: "a/.wh..wh..opq",
			Deleted:  true,
		},
		{
			Path:     "c/foo",
			Whiteout: "a/.wh..wh..opq",
			Deleted:  false,
		},
		{
			Path:     "a/file.wh.txt",
			Whiteout: "a/.wh.file.wh.txt",
			Deleted:  true,
		},
		{
			Path:     "file.wh.d/file.conf",
			Whiteout: "file.wh.d/.wh.file.conf",
			Deleted:  true,
		},
		{
			Path:     "some/file",
			Whiteout: "not/a/white/out",
			Deleted:  false,
		},
		{
			Path:     "a",
			Whiteout: "a/b/.wh..wh..opq",
			Deleted:  false,
		},
		{
			Path:     "a",
			Whiteout: "a/.wh..wh..opq",
			Deleted:  false,
		},
	} {
		got, want := fileIsDeleted(tc.Path, tc.Whiteout), tc.Deleted
		if got != want {
			t.Fail()
		}
		t.Logf("%s, %s\tgot: %v, want: %v", tc.Whiteout, tc.Path, got, want)
	}
}
