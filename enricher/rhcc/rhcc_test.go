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
	io.WriteString(h, name)
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
	//thirdLayerHash := Digest("third layer")
	tests := []struct {
		name   string
		vr     *claircore.VulnerabilityReport
		layers []*claircore.Layer
		want   map[string]string
	}{
		{
			name: "vuln in package in different layer from rhcc package",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
						Kind:           claircore.BINARY,
					},
					"2": {
						Name:    "grafana",
						Version: "v4.7.0",
						Kind:    claircore.BINARY,
					},
				},
				Environments: map[string][]*claircore.Environment{
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: secondLayerHash}},
				},
				Vulnerabilities: map[string]*claircore.Vulnerability{
					"4": {
						Name:           "something bad with grafana",
						FixedInVersion: "v100.0.0",
					},
				},
				PackageVulnerabilities: map[string][]string{
					"2": {"4"},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{firstLayerHash.String(): "1"},
		},
		{
			name: "vuln in package in same layer as rhcc package",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
						Kind:           claircore.BINARY,
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
				Vulnerabilities: map[string]*claircore.Vulnerability{
					"4": {
						Name:           "something bad with grafana",
						FixedInVersion: "v100.0.0",
					},
				},
				PackageVulnerabilities: map[string][]string{
					"2": {"4"},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{firstLayerHash.String(): "1"},
		},
		{
			name: "vuln in package in same layer as rhcc package and rhcc vuln in same layer",
			vr: &claircore.VulnerabilityReport{
				Packages: map[string]*claircore.Package{
					"1": {
						Name:           "some-rh-package-slash-image",
						RepositoryHint: "rhcc",
						Version:        "v1.0.0",
						Kind:           claircore.BINARY,
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
				Vulnerabilities: map[string]*claircore.Vulnerability{
					"4": {
						Name:           "something bad with grafana",
						FixedInVersion: "v100.0.0",
					},
					"5": {
						Name:           "something bad ubi",
						FixedInVersion: "v100.0.0",
					},
				},
				PackageVulnerabilities: map[string][]string{
					"2": {"4"},
					"1": {"5"},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{firstLayerHash.String(): "1"},
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
					"1": {{IntroducedIn: firstLayerHash}},
					"2": {{IntroducedIn: secondLayerHash}},
					"3": {{IntroducedIn: firstLayerHash}},
				},
				Vulnerabilities: map[string]*claircore.Vulnerability{
					"4": {
						Name:           "something bad with grafana",
						FixedInVersion: "v100.0.0",
					},
					"5": {
						Name:           "something bad ubi",
						FixedInVersion: "v100.0.0",
					},
					"6": {
						Name:           "something bad s2i",
						FixedInVersion: "v100.0.0",
					},
				},
				PackageVulnerabilities: map[string][]string{
					"3": {"4"},
					"1": {"5"},
					"2": {"6"},
				},
			},
			layers: []*claircore.Layer{
				{Hash: firstLayerHash},
				{Hash: secondLayerHash},
			},
			want: map[string]string{firstLayerHash.String(): "1", secondLayerHash.String(): "2"},
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
			if tp != "message/vnd.clair.map.layer; enricher=clair.rhcc schema=??" {
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
