package rhcc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

func Digest(name string) claircore.Digest {
	h := sha256.New()
	if _, err := io.WriteString(h, name); err != nil {
		panic(err)
	}
	d, err := claircore.NewDigest("sha256", h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return d
}

func TestEnrich(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)
	firstLayerHash := Digest("first layer")
	secondLayerHash := Digest("second layer")
	tests := []struct {
		name   string
		vr     *claircore.VulnerabilityReport
		layers []*claircore.Layer
		want   map[string]string
	}{
		{
			name: "one package that is a layer one that isn't",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:    "some-rh-package-slash-image",
						Version: "v1.0.0",
						Kind:    claircore.BINARY,
					},
					"2": {
						Name:    "grafana",
						Version: "v4.7.0",
						Kind:    claircore.BINARY,
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash, RepositoryIDs: []string{"1"}}},
					"2": {{IntroducedIn: secondLayerHash}},
				},
				Repositories: map[string]*claircore.Repository{
					"1": {
						ID:   "1",
						Name: "Red Hat Container Catalog",
						URI:  "https://catalog.redhat.com/software/containers/explore",
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{"1": firstLayerHash.String()},
		},
		{
			name: "two packages, neither are layers",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:    "cool app",
						Version: "v1.0.0",
						Kind:    claircore.BINARY,
					},
					"2": {
						Name:    "grafana",
						Version: "v4.7.0",
						Kind:    claircore.BINARY,
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
			want: nil,
		},
		{
			name: "multiple rhcc packages in different layers",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
						Kind:           claircore.BINARY,
					},
					"2": {
						Name:           "some-other-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
						Kind:           claircore.BINARY,
					},
					"3": {
						Name:    "grafana",
						Version: "v4.7.0",
						Kind:    claircore.BINARY,
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash, RepositoryIDs: []string{"1"}}},
					"2": {{IntroducedIn: secondLayerHash, RepositoryIDs: []string{"1"}}},
					"3": {{IntroducedIn: firstLayerHash}},
				},
				Repositories: map[string]*claircore.Repository{
					"1": {
						ID:   "1",
						Name: "Red Hat Container Catalog",
						URI:  "https://catalog.redhat.com/software/containers/explore",
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{"1": firstLayerHash.String(), "2": secondLayerHash.String()},
		},
		{
			name: "multiple rhcc packages in same layers (source and binary)",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:    "some-rh-package-slash-image-binary",
						Version: "v1.0.0",
						Kind:    claircore.BINARY,
						Source: &claircore.Package{
							Name:    "some-rh-package-slash-image-source",
							Version: "v1.0.0",
							Kind:    claircore.SOURCE,
						},
					},
					"2": {
						Name:    "some-rh-package-slash-image-source",
						Version: "v1.0.0",
						Kind:    claircore.SOURCE,
					},
					"3": {
						Name:    "grafana",
						Version: "v4.7.0",
						Kind:    claircore.BINARY,
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash, RepositoryIDs: []string{"1"}}},
					"2": {{IntroducedIn: firstLayerHash, RepositoryIDs: []string{"1"}}},
					"3": {{IntroducedIn: secondLayerHash}},
				},
				Repositories: map[string]*claircore.Repository{
					"1": {
						ID:   "1",
						Name: "Red Hat Container Catalog",
						URI:  "https://catalog.redhat.com/software/containers/explore",
					},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{"1": firstLayerHash.String()},
		},
	}

	e := &Enricher{}
	nog := &noopGetter{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp, data, err := e.Enrich(ctx, nog, tc.vr)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil {
				if data != nil {
					t.Fatal("unexpected data")
				}
				return
			}
			if tp != "message/vnd.clair.map.layer; enricher=clair.rhcc" {
				t.Fatal("wrong type")
			}
			got := make(map[string]string)
			if err := json.Unmarshal(data[0], &got); err != nil {
				t.Error(err)
			}
			if !cmp.Equal(got, tc.want) {
				t.Error(cmp.Diff(got, tc.want))
			}
		})

	}
}

func TestName(t *testing.T) {
	e := &Enricher{}
	if e.Name() != "rhcc" {
		t.Fatal("name should be rhcc")
	}
}

type noopGetter struct{}

func (f *noopGetter) GetEnrichment(ctx context.Context, tags []string) ([]driver.EnrichmentRecord, error) {
	return nil, nil
}
