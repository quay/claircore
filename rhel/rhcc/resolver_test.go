package rhcc

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
			name: "same layer",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"2": {
						Name:    "grafana",
						Version: "v4.7.0",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
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
			name: "different layers",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"2": {
						Name:    "grafana",
						Version: "v4.7.0",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: secondLayerHash}},
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
			name: "different package versions",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"2": {
						Name:    "grafana",
						Version: "v4.7.0",
					},
					"3": {
						Name:    "grafana",
						Version: "v4.8.0",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: firstLayerHash}},
					"3": {{IntroducedIn: secondLayerHash}},
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
			name: "two rh layers",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"2": {
						Name:           "some-rh-other-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"3": {
						Name:    "grafana",
						Version: "v4.8.0",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: secondLayerHash}},
					"3": {{IntroducedIn: secondLayerHash}},
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
			name: "three layers, two rh",
			ir: &claircore.IndexReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"2": {
						Name:           "some-rh-other-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
					},
					"3": {
						Name:    "grafana",
						Version: "v4.8.0",
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: secondLayerHash}},
					"3": {{IntroducedIn: thirdLayerHash}},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
				{Hash: thirdLayerHash},
			},
			lenPackage: 3,
			lenEnvs:    3,
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
