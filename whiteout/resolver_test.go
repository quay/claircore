package whiteout

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/quay/claircore"

	"github.com/quay/zlog"
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

	type testcase struct {
		Name                string
		Report              *claircore.IndexReport
		Layers              []*claircore.Layer
		LenPackage, LenEnvs int
	}

	tests := []testcase{
		{
			Name: "Simple",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			LenPackage: 1,
			LenEnvs:    1,
		},
		{
			Name: "SimpleNoDelete",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			LenPackage: 2,
			LenEnvs:    2,
		},
		{
			Name: "FatFinger",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			LenPackage: 0,
			LenEnvs:    0,
		},
		{
			Name: "MaskedDirectory",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			LenPackage: 2,
			LenEnvs:    2,
		},
		{
			Name: "CommonPrefixDistinctDirs",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			LenPackage: 2,
			LenEnvs:    2,
		},
		{
			Name: "Opaque",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			LenPackage: 0,
			LenEnvs:    0,
		},
		{
			Name: "AddDeleteAdd",
			Report: &claircore.IndexReport{
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
			Layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
				{Hash: thirdLayerHash},
			},
			LenPackage: 1,
			LenEnvs:    1,
		},
	}

	r := &Resolver{}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := zlog.Test(context.Background(), t)
			report := r.Resolve(ctx, tc.Report, tc.Layers)
			if tc.LenPackage != len(report.Packages) {
				t.Fatalf("wrong number of packages: expected: %d got: %d", tc.LenPackage, len(report.Packages))
			}
			if tc.LenEnvs != len(report.Environments) {
				t.Fatalf("wrong number of environments: expected: %d got: %d", tc.LenEnvs, len(report.Environments))
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
